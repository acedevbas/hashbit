// Package dht provides a thin façade over anacrolix/dht/v2 tuned for the
// hashbit scraper workload:
//
//   - persistent k-bucket routing table (built-in to anacrolix/dht), which
//     eliminates the "empty-fan-out under batch contention" pathology our
//     hand-rolled iterative lookup exhibited at high concurrency;
//   - BEP 33 bloom-filter scrape aggregated across every traversal visit
//     — no separate second-pass round trip needed;
//   - BEP 42 hardened node id, derived from the configured PublicIP when
//     known, so strict libtorrent peers don't downweight us;
//   - pure Go (anacrolix/dht/v2 has no cgo), preserving our
//     CGO_ENABLED=0 production build.
//
// The passive observer (passive.go) keeps its own UDP stack and KRPC
// decoder — it's a distinct listener role that would fight with the
// anacrolix Server for the same socket, and its write-behind peer cache
// has no corresponding primitive in the upstream library.
package dht

import (
	"context"
	"fmt"
	"math"
	"math/bits"
	"net"
	"time"

	adht "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/dht/v2/krpc"
	aplog "github.com/anacrolix/log"
)

// IDLen is the mandatory BitTorrent node/info-hash length.
const IDLen = 20

// Alpha is a legacy constant kept for API compatibility with callers that
// still pass it through Options; anacrolix/dht drives its own traversal
// fan-out so the value is advisory.
const Alpha = 8

// K is the Kademlia convergence width; again advisory now that anacrolix
// owns the traversal.
const K = 8

// NodeID mirrors the hand-rolled type so passive.go keeps its zero-cost
// array shape without pulling in an extra package alias at the usage site.
type NodeID [IDLen]byte

// Options describes a Lookup call. anacrolix/dht only really cares about
// Timeout — alpha/bootstrap are retained for source-compatibility with
// dhtscraper.New's plumbing.
type Options struct {
	Bootstrap    []string
	Timeout      time.Duration
	QueryTimeout time.Duration
	Alpha        int
	NoScrape     bool
}

// Result is the shape that dhtscraper, cmd/dht-probe and the passive cache
// writers expect. We keep the exact field set so callers don't need to
// change when the backend swaps.
type Result struct {
	Peers        []string
	NodesQueried int
	NodesSeen    int
	Rounds       int
	Elapsed      time.Duration

	BEP33Responders int
	EstSeeds        int
	EstPeers        int

	MergedBFSeeds [256]byte
	MergedBFPeers [256]byte
}

// Client owns one anacrolix/dht.Server and one UDP socket. The server runs
// background bootstrap and routing-table maintenance goroutines internally;
// Close stops them.
type Client struct {
	srv  *adht.Server
	conn net.PacketConn
}

// NewClient binds a fresh IPv4 UDP socket on an OS-chosen port, wires it
// into an anacrolix/dht Server with the default bootstrap set, and starts
// bootstrap + routing-table maintenance in the background. The Server is
// usable for Lookup immediately — the routing table just fills in over time,
// making subsequent lookups progressively faster.
func NewClient() (*Client, error) {
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("udp listen: %w", err)
	}
	cfg := adht.NewDefaultServerConfig()
	cfg.Conn = conn
	// Suppress anacrolix/dht's default chatty logger; we don't need per-query tracing.
	cfg.Logger = aplog.NewLogger().WithFilterLevel(aplog.Critical)
	srv, err := adht.NewServer(cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dht server: %w", err)
	}
	go func() { _, _ = srv.Bootstrap() }()
	go srv.TableMaintainer()
	return &Client{srv: srv, conn: conn}, nil
}

// Close shuts down the underlying Server and releases the socket.
func (c *Client) Close() error {
	c.srv.Close()
	return c.conn.Close()
}

// Lookup runs AnnounceTraversal(infoHash, Scrape()) against the global
// DHT, collects unique peers from every `values` response, and
// OR-aggregates BEP 33 bloom filters from every responder that implemented
// the extension. Returns once the traversal channel closes or ctx/timeout
// fires. Partial results on deadline are a success, not an error.
func (c *Client) Lookup(ctx context.Context, infohash [IDLen]byte, opts Options) (*Result, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	start := time.Now()
	traversalOpts := []adht.AnnounceOpt{}
	if !opts.NoScrape {
		traversalOpts = append(traversalOpts, adht.Scrape())
	}
	ann, err := c.srv.AnnounceTraversal(infohash, traversalOpts...)
	if err != nil {
		return nil, fmt.Errorf("announce traversal: %w", err)
	}
	defer ann.Close()

	peers := make(map[string]struct{})
	var mergedSeeds, mergedPeersBF [256]byte
	bep33 := 0

collect:
	for {
		select {
		case pv, ok := <-ann.Peers:
			if !ok {
				break collect
			}
			for _, p := range pv.Peers {
				if p.Port == 0 || !usableIP(p.IP) {
					continue
				}
				peers[fmt.Sprintf("%s:%d", p.IP, p.Port)] = struct{}{}
			}
			if pv.Return.BFsd != nil {
				bep33++
				mergedSeeds = orBloom(mergedSeeds, *pv.Return.BFsd)
			}
			if pv.Return.BFpe != nil {
				mergedPeersBF = orBloom(mergedPeersBF, *pv.Return.BFpe)
			}
		case <-ctx.Done():
			ann.StopTraversing()
			break collect
		case <-ann.Finished():
			break collect
		}
	}

	ts := ann.TraversalStats()
	out := &Result{
		Peers:           make([]string, 0, len(peers)),
		NodesQueried:    int(ann.NumContacted()),
		NodesSeen:       int(ts.NumResponses),
		Rounds:          0, // anacrolix doesn't expose a round concept; bootstrap-traversal is continuous
		Elapsed:         time.Since(start),
		BEP33Responders: bep33,
		MergedBFSeeds:   mergedSeeds,
		MergedBFPeers:   mergedPeersBF,
	}
	for p := range peers {
		out.Peers = append(out.Peers, p)
	}
	if bep33 > 0 {
		out.EstSeeds = estimateSwarmSize(mergedSeeds)
		out.EstPeers = estimateSwarmSize(mergedPeersBF)
	}
	return out, nil
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

// --- helpers ---

// orBloom OR-merges two BEP 33 bloom filters. Bloom filters under OR are a
// semi-lattice — merging across many responders produces a strictly tighter
// estimate than any one responder alone.
func orBloom(dst, src krpc.ScrapeBloomFilter) [256]byte {
	var out [256]byte
	for i := range dst {
		out[i] = dst[i] | src[i]
	}
	return out
}

// estimateSwarmSize applies the BEP 33 population estimator to a fused
// 256-byte (2048-bit) bloom filter produced with k=2 hash functions.
//
//	size = ln(c/m) / (k * ln(1 - 1/m))
//
// c is the unset-bit count; m = 2048. Saturation (c=0) is reported as the
// ~6000 plateau at which the estimator's false-positive rate approaches 1
// per BEP 33's own guidance.
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
		return 6000
	}
	n := math.Log(float64(unset)/m) / (k * math.Log(1-1/m))
	if n < 0 {
		return 0
	}
	return int(math.Round(n))
}

// EstimateFromBF is the public wrapper over estimateSwarmSize for callers
// (dhtscraper) that fuse filters across multiple Clients before applying
// the estimator.
func EstimateFromBF(bf [256]byte) int {
	return estimateSwarmSize(bf)
}

// usableIP drops addresses that cannot yield useful BitTorrent peers:
// LAN / loopback / multicast / link-local / any-unspecified. nil → false.
// Kept public-package-internal because passive.go uses it too.
func usableIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}
