// Package dht implements a minimal BitTorrent Mainline DHT client (BEP 5) —
// specifically the iterative get_peers lookup — with no routing table, no
// persistent server role, no announce. Each Lookup opens one UDP socket,
// queries well-known routers, then iteratively walks the k-closest nodes to
// the target info_hash until either top-K converge or the deadline fires.
//
// Protocol-level choices follow current best practice:
//   - α = 3 concurrent in-flight queries per iteration round
//   - K = 8 closest-nodes convergence condition
//   - 4-byte transaction_id to tolerate high-rate bursts without collisions
//   - RFC 1918 / loopback / link-local / multicast peers dropped at parse time
//   - Per-query timeout strictly bounds each datagram; no exponential backoff
//     because the whole lookup has a single outer deadline
package dht

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/acedevbas/hashbit/internal/bencode"
)

const (
	IDLen        = 20
	K            = 8
	Alpha        = 3
	maxRounds    = 25  // safety cap on iteration rounds
	maxShortlist = 256 // cap memory for pathological networks
)

// DefaultBootstrap is a curated list of Mainline DHT routers. These nodes do
// not serve peer data directly — they hand back closer nodes from their
// routing tables. Reachability varies over time; extra redundancy is cheap.
// Each router roots a slightly different subgraph of the DHT, so hitting
// more of them at startup widens the initial candidate set.
var DefaultBootstrap = []string{
	"router.bittorrent.com:6881",
	"router.utorrent.com:6881",
	"dht.transmissionbt.com:6881",
	"dht.libtorrent.org:25401",
	"router.silotis.us:6881",
	"dht.aelitis.com:6881",
	"router.bitcomet.com:6881",
	"dht.anacrolix.link:42069",
	"bootstrap.jami.net:4222",
	"router.bittorrent.cloud:42069",
	"dht.libtorrent.org:6881",
}

type NodeID [IDLen]byte

type node struct {
	id   NodeID // zero until the node responds
	addr *net.UDPAddr
}

// network identifies the address family a Client is bound to. "udp4" and
// "udp6" are the only accepted values; the zero string is treated as udp4
// for backwards-compatibility with callers of the original NewClient.
func normalizeNetwork(n string) string {
	switch n {
	case "udp6":
		return "udp6"
	default:
		return "udp4"
	}
}

// Options configures one Lookup. Zero-valued fields pick sensible defaults.
type Options struct {
	Bootstrap    []string
	Timeout      time.Duration // overall lookup deadline
	QueryTimeout time.Duration // per-datagram response deadline
	Alpha        int           // parallelism factor

	// NoScrape disables the BEP 33 scrape=1 flag in outbound queries.
	// Some DHT implementations return bloom filters INSTEAD of the values
	// array when scrape is set, shrinking raw-peer yield to near-zero.
	// Set true to collect only values (classic behavior).
	NoScrape bool
}

// Result is returned by Lookup.
type Result struct {
	Peers        []string // unique "ip:port", IPv4 only in this implementation
	NodesQueried int
	NodesSeen    int
	Rounds       int
	Elapsed      time.Duration

	// BEP 33 aggregated swarm-size estimate. Each DHT node that implements
	// BEP 33 returns 256-byte bloom filters of seeds and peers it knows about;
	// we OR them across all responders and derive a population estimate from
	// the unset-bit count. Zero when no responder implements BEP 33.
	BEP33Responders int
	EstSeeds        int
	EstPeers        int

	// Raw merged bloom filters. Exposed so callers that union results across
	// multiple Clients (each with a distinct node id) can OR these together
	// before applying the population estimator — combining bit vectors gives
	// a more accurate count than taking max(estimate_per_client).
	MergedBFSeeds [256]byte
	MergedBFPeers [256]byte
}

// EstimateFromBF applies the BEP 33 population-size estimator to a fused
// bloom filter produced by OR-ing `MergedBFSeeds`/`MergedBFPeers` across
// multiple Lookup results.
func EstimateFromBF(bf [256]byte) int {
	return estimateSwarmSize(bf)
}

// Client is a long-lived DHT lookup handle sharing one UDP socket across many
// concurrent Lookup calls. Transaction IDs multiplex the single socket, so
// scaling up to hundreds of concurrent lookups from one Client is cheaper
// than opening a fresh socket each time — the usual win is eliminating ~100ms
// of connect overhead per hash when scraping a large batch.
//
// Safe for concurrent use. Close the client when done to release the socket.
type Client struct {
	srv    *server
	conn   *net.UDPConn
	selfID NodeID

	// network is "udp4" or "udp6". Used for bootstrap resolution so an IPv6
	// client resolves DefaultBootstrap hostnames to AAAA records and walks
	// the IPv6 keyspace exclusively. A mixed IPv4/IPv6 pool is built by
	// constructing one Client per family.
	network string

	// extMu guards externalIP. Reads hit the fast path on every dispatched
	// reply (hundreds per second during a lookup), writes happen at most once
	// per IP change — RWMutex trades one extra atomic per read for lockless
	// rekey decisions.
	extMu      sync.RWMutex
	externalIP net.IP
}

// Network returns "udp4" or "udp6" — the address family this client is
// bound to. Callers that need to route traffic along a specific family
// can use this to pick between clients in a mixed pool.
func (c *Client) Network() string { return c.network }

// NewClient binds a new IPv4 UDP socket on an OS-chosen port, generates a
// random node id, and starts the KRPC dispatcher. The client is usable
// immediately after this returns. The id is upgraded to a BEP 42 derivation
// automatically the first time a peer echoes our observed public IPv4.
func NewClient() (*Client, error) {
	return newClient("udp4", nil)
}

// NewClient6 is the IPv6 variant. Same behaviour as NewClient but binds
// udp6 and resolves bootstrap hostnames to AAAA records. Nodes returned
// over the v6 socket are exclusively IPv6, and the client yields IPv6 peer
// strings formatted as `[addr]:port`.
func NewClient6() (*Client, error) {
	return newClient("udp6", nil)
}

// NewClientWithIP seeds the client with a BEP 42-compliant id derived from
// the supplied public IPv4. Prefer this when the caller already knows the
// external address (e.g. via STUN or a prior lookup), since it avoids the
// first-query window where peers still see a random id.
func NewClientWithIP(ip net.IP) (*Client, error) {
	return newClient("udp4", ip)
}

func newClient(network string, ip net.IP) (*Client, error) {
	network = normalizeNetwork(network)
	var (
		selfID NodeID
		err    error
	)
	if ip4 := ip.To4(); ip4 != nil && network == "udp4" {
		selfID, err = bep42NodeID(ip4)
	} else {
		_, err = rand.Read(selfID[:])
	}
	if err != nil {
		return nil, fmt.Errorf("gen id: %w", err)
	}
	var laddr *net.UDPAddr
	if network == "udp6" {
		laddr = &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}
	} else {
		laddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, fmt.Errorf("udp listen %s: %w", network, err)
	}
	srv := newServer(conn, selfID)
	c := &Client{srv: srv, conn: conn, selfID: selfID, network: network}
	if ip4 := ip.To4(); ip4 != nil && network == "udp4" {
		c.externalIP = append(net.IP(nil), ip4...)
	}
	srv.onObservedIP = c.observeIP
	go srv.readLoopUntilClose()
	return c, nil
}

// SetExternalIP regenerates selfID as a BEP 42 derivation of ip and publishes
// the new id to the running server so subsequent outbound queries advertise
// it. Safe to call from any goroutine.
func (c *Client) SetExternalIP(ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil || !usableIP(ip4) {
		return
	}
	newID, err := bep42NodeID(ip4)
	if err != nil {
		return
	}
	c.extMu.Lock()
	c.externalIP = append(net.IP(nil), ip4...)
	c.selfID = newID
	c.extMu.Unlock()

	c.srv.mu.Lock()
	c.srv.selfID = newID
	c.srv.mu.Unlock()
}

// ObservedIPFromResponse extracts the "ip" key from a decoded KRPC response
// envelope (BEP 42 response echo) and, if it differs from the currently
// assumed external IP, upgrades selfID to a BEP 42-derived id. Exposed so
// callers that decode KRPC responses outside the built-in dispatcher (e.g.
// passive receivers) can still feed the learning loop.
func (c *Client) ObservedIPFromResponse(top map[string]any) {
	ip := extractObservedIPv4(top)
	if ip == nil {
		return
	}
	c.observeIP(ip)
}

// observeIP decides whether the observed address warrants a rekey. It
// deliberately rekeys on the first observation too — starting with a random
// id and upgrading mid-lookup is strictly better than never upgrading.
func (c *Client) observeIP(ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	c.extMu.RLock()
	same := c.externalIP.Equal(ip4)
	c.extMu.RUnlock()
	if same {
		return
	}
	c.SetExternalIP(ip4)
}

// Close shuts down the shared socket and causes the read loop to exit. Any
// in-flight Lookup calls on this client will unblock with an error shortly
// after.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Lookup performs an iterative DHT get_peers for infohash and returns every
// unique peer endpoint discovered plus (when any responder implements BEP 33)
// a bloom-filter-aggregated swarm-size estimate. A partial result on deadline
// is a success, not an error.
func (c *Client) Lookup(ctx context.Context, infohash [IDLen]byte, opts Options) (*Result, error) {
	if opts.Alpha == 0 {
		opts.Alpha = Alpha
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.QueryTimeout == 0 {
		opts.QueryTimeout = 2 * time.Second
	}
	if len(opts.Bootstrap) == 0 {
		opts.Bootstrap = DefaultBootstrap
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	srv := c.srv

	target := NodeID(infohash)

	bsAddrs := resolveBootstrapNetwork(opts.Bootstrap, c.network)
	if len(bsAddrs) == 0 {
		return nil, errors.New("no bootstrap nodes resolved")
	}

	queried := make(map[string]bool)
	seen := make(map[string]bool) // every addr we've added to shortlist
	shortlist := make([]node, 0, 128)
	peers := make(map[string]struct{})

	// BEP 33 merged bloom filters (OR'ed across all responders).
	var mergedSeeds, mergedPeers [256]byte
	bep33Responders := 0

	// batchQuery fires α (or fewer) get_peers in parallel and folds responses.
	// scrape controls whether the BEP 33 scrape=1 flag is set in outbound
	// queries; BEP 33-compliant responders return bloom filters INSTEAD of
	// values when scrape is set, so the main walk keeps scrape=false and a
	// final targeted round at the end flips it on to harvest filters only.
	batchQuery := func(batch []node, scrape bool) bool {
		if len(batch) == 0 {
			return false
		}
		respCh := make(chan response, len(batch))
		for _, n := range batch {
			queried[n.addr.String()] = true
			go func(n node) {
				r, err := srv.getPeers(ctx, n.addr, target, opts.QueryTimeout, scrape)
				if err != nil {
					respCh <- response{}
					return
				}
				respCh <- r
			}(n)
		}
		anyResp := false
		for i := 0; i < len(batch); i++ {
			r := <-respCh
			if r.sender == nil {
				continue
			}
			anyResp = true
			for _, p := range r.values {
				peers[p] = struct{}{}
			}
			for _, nn := range r.nodes {
				key := nn.addr.String()
				if seen[key] {
					continue
				}
				if !usableIP(nn.addr.IP) || nn.addr.Port == 0 {
					continue
				}
				// Filter nodes by our socket family: a udp4 socket can't dial
				// an IPv6 address and vice versa. Mixed replies commonly
				// arrive because we set want=["n4","n6"] in every query.
				if !matchesNetwork(c.network, nn.addr.IP) {
					continue
				}
				seen[key] = true
				shortlist = append(shortlist, nn)
			}
			if r.hasBF {
				bep33Responders++
				for i := 0; i < 256; i++ {
					mergedSeeds[i] |= r.bfSeeds[i]
					mergedPeers[i] |= r.bfPeers[i]
				}
			}
		}
		return anyResp
	}

	// --- Round 0: bootstrap burst ---
	bsNodes := make([]node, 0, len(bsAddrs))
	for _, a := range bsAddrs {
		bsNodes = append(bsNodes, node{addr: a})
		seen[a.String()] = true
	}
	batchQuery(bsNodes, false)

	// --- Iterative lookup ---
	rounds := 0
	for rounds < maxRounds {
		if ctx.Err() != nil {
			break
		}
		sortByDistance(shortlist, target)
		if len(shortlist) > maxShortlist {
			shortlist = shortlist[:maxShortlist]
		}

		batch := make([]node, 0, opts.Alpha)
		for _, n := range shortlist {
			if queried[n.addr.String()] {
				continue
			}
			batch = append(batch, n)
			if len(batch) >= opts.Alpha {
				break
			}
		}
		if len(batch) == 0 {
			break
		}

		batchQuery(batch, false)
		rounds++

		// Convergence: if the K closest known nodes have all been queried,
		// further iteration would only chase equal-or-farther nodes.
		sortByDistance(shortlist, target)
		top := shortlist
		if len(top) > K {
			top = top[:K]
		}
		allQueried := true
		for _, n := range top {
			if !queried[n.addr.String()] {
				allQueried = false
				break
			}
		}
		if allQueried {
			break
		}
	}

	// Final BEP 33 scrape round against every node we've already talked to.
	// BEP 33-aware responders are sparse (~10-20% of network) and scattered
	// across the keyspace, not clustered at top-K, so re-querying the whole
	// visited set maximises the number of bloom filters we collect. Cost is
	// bounded: at most maxShortlist UDP packets, completes in ~1-2 seconds.
	if !opts.NoScrape && len(queried) > 0 && ctx.Err() == nil {
		type addrNode struct{ a *net.UDPAddr }
		targets := make([]*net.UDPAddr, 0, len(queried))
		for _, n := range shortlist {
			if queried[n.addr.String()] {
				targets = append(targets, n.addr)
			}
		}
		respCh := make(chan response, len(targets))
		for _, a := range targets {
			go func(addr *net.UDPAddr) {
				r, err := srv.getPeers(ctx, addr, target, opts.QueryTimeout, true)
				if err != nil {
					respCh <- response{}
					return
				}
				respCh <- r
			}(a)
		}
		for i := 0; i < len(targets); i++ {
			r := <-respCh
			if r.hasBF {
				bep33Responders++
				for j := 0; j < 256; j++ {
					mergedSeeds[j] |= r.bfSeeds[j]
					mergedPeers[j] |= r.bfPeers[j]
				}
			}
			for _, p := range r.values {
				peers[p] = struct{}{}
			}
		}
		rounds++
	}

	res := &Result{
		Peers:           make([]string, 0, len(peers)),
		NodesQueried:    len(queried),
		NodesSeen:       len(seen),
		Rounds:          rounds,
		Elapsed:         time.Since(start),
		BEP33Responders: bep33Responders,
	}
	for p := range peers {
		res.Peers = append(res.Peers, p)
	}
	sort.Strings(res.Peers)

	if bep33Responders > 0 {
		res.EstSeeds = estimateSwarmSize(mergedSeeds)
		res.EstPeers = estimateSwarmSize(mergedPeers)
	}
	res.MergedBFSeeds = mergedSeeds
	res.MergedBFPeers = mergedPeers
	return res, nil
}

// SampleInfoHashes issues a BEP 51 sample_infohashes query to addr. The
// remote node, if it supports BEP 51, returns a list of 20-byte infohashes
// currently indexed in its routing table plus a list of closer nodes.
// Callers walk the keyspace by iteratively following returned nodes.
// Returns the parsed samples, closer nodes, and the responder's node id.
func (c *Client) SampleInfoHashes(ctx context.Context, addr *net.UDPAddr, target NodeID, timeout time.Duration) ([][IDLen]byte, []node, NodeID, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	r, err := c.srv.sampleInfoHashes(ctx, addr, target, timeout)
	if err != nil {
		return nil, nil, NodeID{}, err
	}
	if r.sender == nil {
		return nil, nil, NodeID{}, errors.New("empty response")
	}
	return r.samples, r.nodes, r.nodeID, nil
}

// BootstrapAddrs returns the default Mainline bootstrap endpoints already
// resolved to *net.UDPAddr. Exposed for the BEP 51 crawler which needs to
// seed its walk from known good nodes — callers outside this package should
// not construct the node list manually because DefaultBootstrap uses
// hostnames that must be DNS-resolved first.
func BootstrapAddrs() []*net.UDPAddr {
	return resolveBootstrap(DefaultBootstrap)
}

// Lookup is a convenience wrapper that creates a one-shot Client, runs a
// single Lookup, and tears down the socket. For bulk scraping prefer
// NewClient + client.Lookup: it reuses one socket across many queries.
func Lookup(ctx context.Context, infohash [IDLen]byte, opts Options) (*Result, error) {
	c, err := NewClient()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Lookup(ctx, infohash, opts)
}

// --- KRPC server: single UDP socket + txid-based dispatcher ---

type response struct {
	nodeID NodeID
	sender *net.UDPAddr
	values []string // parsed "ip:port"
	nodes  []node   // closer nodes returned in the KRPC response

	// BEP 33: if this responder implemented bloom-filter scrape, these hold
	// its 256-byte seed / peer filters. hasBF = false means no BEP 33 data.
	hasBF   bool
	bfSeeds [256]byte
	bfPeers [256]byte

	// BEP 51: samples is populated when this response is the reply to a
	// sample_infohashes query. Each entry is a 20-byte raw infohash the
	// remote node is currently tracking. Length is bounded by the responder
	// (usually ≤20 samples per call by spec recommendation).
	samples [][IDLen]byte
}

type server struct {
	conn    *net.UDPConn
	selfID  NodeID
	mu      sync.Mutex
	pending map[uint32]chan response
	txSeq   uint32

	// onObservedIP is invoked (if non-nil) with the public IPv4 each time a
	// peer echoes our apparent external address in the "ip" response field.
	// The Client sets this to its rekey hook; leaving it nil is harmless.
	onObservedIP func(net.IP)
}

func newServer(conn *net.UDPConn, selfID NodeID) *server {
	return &server{
		conn:    conn,
		selfID:  selfID,
		pending: make(map[uint32]chan response),
	}
}

// readLoopUntilClose blocks on the socket and dispatches KRPC responses
// until Close closes the connection. One goroutine per Client.
func (s *server) readLoopUntilClose() {
	buf := make([]byte, 2048)
	for {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed — end of life
		}
		data := append([]byte(nil), buf[:n]...)
		go s.dispatch(data, src)
	}
}

func (s *server) dispatch(data []byte, src *net.UDPAddr) {
	v, err := bencode.Decode(data)
	if err != nil {
		return
	}
	top, ok := bencode.AsDict(v)
	if !ok {
		return
	}
	// BEP 42: responders echo our apparent public endpoint in a top-level
	// "ip" key. Harvest it before any early returns below so we still learn
	// from error replies.
	if s.onObservedIP != nil {
		if ip := extractObservedIPv4(top); ip != nil {
			s.onObservedIP(ip)
		}
	}
	txB, ok := bencode.DictBytes(top, "t")
	if !ok || len(txB) < 4 {
		return
	}
	txid := binary.BigEndian.Uint32(txB[:4])
	y, _ := bencode.DictString(top, "y")
	if y != "r" {
		// y == "e" (error) or unexpected — wake the waiter with an empty
		// response so it doesn't hit the per-query timeout for free.
		s.deliver(txid, response{})
		return
	}
	r, ok := bencode.AsDict(top["r"])
	if !ok {
		s.deliver(txid, response{})
		return
	}
	resp := response{sender: src}
	if idB, ok := bencode.DictBytes(r, "id"); ok && len(idB) == IDLen {
		copy(resp.nodeID[:], idB)
	}
	// values: bencoded list of 6-byte (IPv4) or 18-byte (IPv6, BEP 32) compact peers.
	if valsAny, ok := r["values"]; ok {
		if arr, ok := valsAny.([]any); ok {
			for _, it := range arr {
				b, ok := it.([]byte)
				if !ok {
					continue
				}
				if len(b) == 6 {
					ip := net.IPv4(b[0], b[1], b[2], b[3])
					port := binary.BigEndian.Uint16(b[4:6])
					if port == 0 || !usableIP(ip) {
						continue
					}
					resp.values = append(resp.values, fmt.Sprintf("%s:%d", ip, port))
				} else if len(b) == 18 {
					ip := net.IP(append([]byte(nil), b[:16]...))
					port := binary.BigEndian.Uint16(b[16:18])
					if port == 0 || !usableIP(ip) {
						continue
					}
					resp.values = append(resp.values, fmt.Sprintf("[%s]:%d", ip, port))
				}
			}
		}
	}
	// values6: some implementations split IPv6 peers into a dedicated field
	// instead of mixing them into values. Parse both formats defensively.
	if v6Any, ok := r["values6"]; ok {
		if arr, ok := v6Any.([]any); ok {
			for _, it := range arr {
				b, ok := it.([]byte)
				if !ok || len(b) != 18 {
					continue
				}
				ip := net.IP(append([]byte(nil), b[:16]...))
				port := binary.BigEndian.Uint16(b[16:18])
				if port == 0 || !usableIP(ip) {
					continue
				}
				resp.values = append(resp.values, fmt.Sprintf("[%s]:%d", ip, port))
			}
		}
	}
	// nodes: concatenated 26-byte compact IPv4 nodes.
	if nb, ok := bencode.DictBytes(r, "nodes"); ok {
		for i := 0; i+26 <= len(nb); i += 26 {
			var nid NodeID
			copy(nid[:], nb[i:i+20])
			ip := net.IPv4(nb[i+20], nb[i+21], nb[i+22], nb[i+23])
			port := binary.BigEndian.Uint16(nb[i+24 : i+26])
			if port == 0 {
				continue
			}
			resp.nodes = append(resp.nodes, node{
				id:   nid,
				addr: &net.UDPAddr{IP: ip, Port: int(port)},
			})
		}
	}
	// nodes6 (BEP 32): concatenated 38-byte compact IPv6 nodes. Parsed
	// unconditionally so that dual-stack responders received over an IPv6
	// socket yield usable closer-nodes, and v4 clients that happened to
	// receive nodes6 in a mixed reply simply ignore them later when
	// usableIP returns true but the address family mismatches the dialer.
	if nb, ok := bencode.DictBytes(r, "nodes6"); ok {
		const entry = 38
		for i := 0; i+entry <= len(nb); i += entry {
			var nid NodeID
			copy(nid[:], nb[i:i+20])
			ip := net.IP(append([]byte(nil), nb[i+20:i+36]...))
			port := binary.BigEndian.Uint16(nb[i+36 : i+38])
			if port == 0 {
				continue
			}
			resp.nodes = append(resp.nodes, node{
				id:   nid,
				addr: &net.UDPAddr{IP: ip, Port: int(port)},
			})
		}
	}
	// BEP 33 bloom-filter fields. Present iff the responder implements it.
	if bf, ok := bencode.DictBytes(r, "BFsd"); ok && len(bf) == 256 {
		copy(resp.bfSeeds[:], bf)
		resp.hasBF = true
	}
	if bf, ok := bencode.DictBytes(r, "BFpe"); ok && len(bf) == 256 {
		copy(resp.bfPeers[:], bf)
		resp.hasBF = true
	}
	// BEP 51 sample_infohashes reply: a "samples" byte-string whose length is
	// a multiple of 20. Each 20-byte slice is one infohash currently indexed
	// by the responding node. Dispatched here so a single read loop serves
	// both get_peers and sample_infohashes replies.
	if samplesB, ok := bencode.DictBytes(r, "samples"); ok && len(samplesB) >= IDLen && len(samplesB)%IDLen == 0 {
		n := len(samplesB) / IDLen
		resp.samples = make([][IDLen]byte, n)
		for i := 0; i < n; i++ {
			copy(resp.samples[i][:], samplesB[i*IDLen:(i+1)*IDLen])
		}
	}
	s.deliver(txid, resp)
}

func (s *server) deliver(txid uint32, r response) {
	s.mu.Lock()
	ch, ok := s.pending[txid]
	if ok {
		delete(s.pending, txid)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- r:
	default:
	}
}

// sampleInfoHashes issues a BEP 51 sample_infohashes query to addr and waits
// for the reply. The target is a random 20-byte id used purely for protocol
// compliance — BEP 51 responders return samples of their stored hashes
// regardless of the target. Returns the parsed response or a timeout.
func (s *server) sampleInfoHashes(ctx context.Context, addr *net.UDPAddr, target NodeID, timeout time.Duration) (response, error) {
	s.mu.Lock()
	s.txSeq++
	txid := s.txSeq
	ch := make(chan response, 1)
	s.pending[txid] = ch
	selfID := s.selfID
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, txid)
		s.mu.Unlock()
	}()

	var txB [4]byte
	binary.BigEndian.PutUint32(txB[:], txid)
	msg := encodeSampleInfoHashes(txB, selfID, target)
	if _, err := s.conn.WriteToUDP(msg, addr); err != nil {
		return response{}, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r, nil
	case <-timer.C:
		return response{}, errors.New("sample_infohashes timeout")
	case <-ctx.Done():
		return response{}, ctx.Err()
	}
}

func (s *server) getPeers(ctx context.Context, addr *net.UDPAddr, target NodeID, timeout time.Duration, scrape bool) (response, error) {
	s.mu.Lock()
	s.txSeq++
	txid := s.txSeq
	ch := make(chan response, 1)
	s.pending[txid] = ch
	// Snapshot selfID under the same lock that guards mutation from
	// Client.SetExternalIP — encoding outside the lock would otherwise race.
	selfID := s.selfID
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, txid)
		s.mu.Unlock()
	}()

	var txB [4]byte
	binary.BigEndian.PutUint32(txB[:], txid)
	msg := encodeGetPeers(txB, selfID, target, scrape)
	if _, err := s.conn.WriteToUDP(msg, addr); err != nil {
		return response{}, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r, nil
	case <-timer.C:
		return response{}, errors.New("query timeout")
	case <-ctx.Done():
		return response{}, ctx.Err()
	}
}

// encodeSampleInfoHashes serializes a BEP 51 sample_infohashes query. Keys
// inside "a" are lexicographic: id < target.
//
//	d1:ad2:id20:<self_id>6:target20:<target>e1:q17:sample_infohashes1:t4:<tx>1:y1:qe
func encodeSampleInfoHashes(txid [4]byte, selfID NodeID, target NodeID) []byte {
	buf := make([]byte, 0, 96)
	buf = append(buf, "d1:ad2:id20:"...)
	buf = append(buf, selfID[:]...)
	buf = append(buf, "6:target20:"...)
	buf = append(buf, target[:]...)
	buf = append(buf, "e1:q17:sample_infohashes1:t4:"...)
	buf = append(buf, txid[:]...)
	buf = append(buf, "1:y1:qe"...)
	return buf
}

// encodeGetPeers serializes a fixed-shape KRPC query. Set keys in args are
// always lexicographic per BEP 5 — order here is id < info_hash < scrape <
// want. Non-aware nodes ignore unknown keys.
//
//   - BEP 33: scrape=1 asks compliant nodes to add bloom filters (BFsd/BFpe)
//   - BEP 32: want=["n4","n6"] asks the node to return IPv6 nodes/values too
//     (field names `nodes6` and `values6` in the response).
func encodeGetPeers(txid [4]byte, selfID NodeID, target NodeID, scrape bool) []byte {
	buf := make([]byte, 0, 128)
	buf = append(buf, "d1:ad2:id20:"...)
	buf = append(buf, selfID[:]...)
	buf = append(buf, "9:info_hash20:"...)
	buf = append(buf, target[:]...)
	if scrape {
		buf = append(buf, "6:scrapei1e"...)
	}
	// BEP 32 want list: "4:want" key, value = list of byte-strings.
	//   l2:n42:n6e  →  list ["n4","n6"]
	buf = append(buf, "4:wantl2:n42:n6e"...)
	buf = append(buf, "e1:q9:get_peers1:t4:"...)
	buf = append(buf, txid[:]...)
	buf = append(buf, "1:y1:qe"...)
	return buf
}

// estimateSwarmSize applies the BEP 33 population-size estimator to a 256-byte
// (2048-bit) bloom filter produced with k=2 hash functions.
//
//	size = ln(c/m) / (k * ln(1 - 1/m))
//
// where c is the number of UNSET bits and m = 2048. Saturated filters (c=0)
// are reported as the worst-case capacity of ~6000 at which false-positive
// probability approaches 1 (BEP 33 documents this cliff). Empty filters
// return 0 directly.
func estimateSwarmSize(bf [256]byte) int {
	const m = 2048.0
	const k = 2.0
	unset := 0
	for _, b := range bf {
		unset += 8 - bits.OnesCount8(b)
	}
	if unset == int(m) {
		return 0
	}
	if unset == 0 {
		return 6000 // saturation plateau
	}
	n := math.Log(float64(unset)/m) / (k * math.Log(1-1/m))
	if n < 0 {
		return 0
	}
	return int(math.Round(n))
}

// --- helpers ---

func resolveBootstrap(hosts []string) []*net.UDPAddr {
	return resolveBootstrapNetwork(hosts, "udp4")
}

// resolveBootstrapNetwork resolves hostnames using the specified network
// family. "udp4" picks the A record, "udp6" picks AAAA. Hosts without a
// record in the requested family are silently skipped — this keeps the
// v4 and v6 pools independent even when only a subset of the default
// bootstrap list has dual-stack presence.
func resolveBootstrapNetwork(hosts []string, network string) []*net.UDPAddr {
	network = normalizeNetwork(network)
	out := make([]*net.UDPAddr, 0, len(hosts))
	for _, h := range hosts {
		a, err := net.ResolveUDPAddr(network, h)
		if err == nil {
			out = append(out, a)
		}
	}
	return out
}

// matchesNetwork reports whether an IP is reachable on the client's socket
// family. "udp4" accepts IPv4; "udp6" accepts IPv6. IPv4-mapped v6 addresses
// (e.g. ::ffff:1.2.3.4) are treated as IPv4 — they're rare in DHT replies
// but match what the kernel would dial anyway.
func matchesNetwork(network string, ip net.IP) bool {
	isV4 := ip.To4() != nil
	switch normalizeNetwork(network) {
	case "udp6":
		return !isV4
	default:
		return isV4
	}
}

// usableIP drops addresses that cannot yield useful BitTorrent peers: LAN,
// loopback, multicast, link-local, anything-0.0.0.0. nil IP returns false.
func usableIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

func sortByDistance(list []node, target NodeID) {
	sort.Slice(list, func(i, j int) bool {
		for k := 0; k < IDLen; k++ {
			di := list[i].id[k] ^ target[k]
			dj := list[j].id[k] ^ target[k]
			if di != dj {
				return di < dj
			}
		}
		return false
	})
}
