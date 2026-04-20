// Passive DHT participant ("Sybil-lite"). Listens on a stable UDP port and
// responds to incoming KRPC queries so that remote clients routing through the
// DHT keyspace add us to their routing tables. Every time a peer issues
// announce_peer to us we learn a real (infohash, ip:port) swarm member; over
// long periods the passive cache becomes a live snapshot of the public swarm.
//
// Design trade-offs:
//   - We are NOT a full Kademlia router. We do not maintain a routing table,
//     and we reply to find_node / get_peers with empty "nodes" / "values".
//     That slightly degrades routing for queriers, but our value to them is
//     existing in their routing table as a well-behaved endpoint — they still
//     announce_peer to us, which is the only message we actually mine.
//   - Tokens are HMAC-SHA256(secret, remote_ip)[:8] with a rotating secret
//     (10-minute cycle, 2 generations valid). Cheap, stateless, and resistant
//     to simple spoof attempts.
//   - We accept announce_peer with bad/stale tokens too (observation mode):
//     correctness of someone else's announce is not our concern. The token
//     path remains strict for future public-facing use.
//
// Ethics: the peer-data we record is exactly the data clients broadcast into
// the public DHT swarm of their own volition. We do not probe, we do not
// amplify, we only listen and persist.
package dht

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acedevbas/hashbit/internal/bencode"
	"github.com/acedevbas/hashbit/internal/metrics"
)

// PeerRecorder is the write-side of the passive cache. Implementations persist
// each observed (infohash, ip:port) pair; typically the concrete impl batches
// to PostgreSQL behind a buffered channel (see peercache.go).
type PeerRecorder interface {
	Record(infohash, peer string)
}

// PassiveOptions configures a PassiveNode. Zero-valued fields pick defaults.
type PassiveOptions struct {
	// Port to bind. Must be stable — peers remember our (ip,port) when they
	// add us to their routing table, and a changing port discards that.
	Port int
	// NodeID override; if zero we start with a random id and upgrade to a
	// BEP 42 derivation as soon as a responder echoes our external IPv4.
	NodeID NodeID
	// TokenRotation is the secret-rotation interval. BEP 5 recommends 5-10
	// minutes; a longer window grows replay tolerance at the cost of token
	// freshness guarantees. Default 10m.
	TokenRotation time.Duration
	// Recorder receives every observed announce_peer. If nil, announces are
	// parsed and discarded (useful for dry-run).
	Recorder PeerRecorder
}

// PassiveNode is the long-running receiver. Construct with NewPassiveNode,
// call Start to begin answering queries, and Close to release the socket.
//
// Safe for concurrent use after Start. The underlying UDP socket is distinct
// from any lookup Client — the two do not share state.
type PassiveNode struct {
	conn *net.UDPConn
	opts PassiveOptions

	idMu     sync.RWMutex
	selfID   NodeID
	observed net.IP // cached external IPv4 for BEP 42 upgrades

	// Token rotation: keep the current and previous secret so a token issued
	// up to 2*TokenRotation ago is still accepted. Older tokens are rejected
	// to bound replay windows.
	tokMu     sync.RWMutex
	curSecret [32]byte
	prvSecret [32]byte
	hasPrv    bool

	// Counters for observability. Cheap atomics — fetched by a future metrics
	// endpoint or debug log without locking.
	queriesRecv  atomic.Uint64
	announcesRec atomic.Uint64

	closeOnce sync.Once
	closed    chan struct{}
}

// NewPassiveNode binds a stable UDP port. The socket is opened eagerly so that
// port-conflict errors surface at startup rather than after Start spawns its
// goroutine. Start returns quickly; the receive loop runs in the background.
func NewPassiveNode(opts PassiveOptions) (*PassiveNode, error) {
	if opts.Port == 0 {
		opts.Port = 6881
	}
	if opts.TokenRotation <= 0 {
		opts.TokenRotation = 10 * time.Minute
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: opts.Port})
	if err != nil {
		return nil, fmt.Errorf("passive dht udp listen :%d: %w", opts.Port, err)
	}
	n := &PassiveNode{
		conn:   conn,
		opts:   opts,
		closed: make(chan struct{}),
	}
	if opts.NodeID != (NodeID{}) {
		n.selfID = opts.NodeID
	} else if _, err := rand.Read(n.selfID[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("gen passive node id: %w", err)
	}
	if _, err := rand.Read(n.curSecret[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("gen token secret: %w", err)
	}
	return n, nil
}

// Start launches the receive loop and the token rotator. Both stop when the
// context is cancelled or Close is called. Returns immediately.
func (n *PassiveNode) Start(ctx context.Context) {
	go n.readLoop(ctx)
	go n.rotateTokens(ctx)
}

// Close shuts down the UDP socket, which causes readLoop to exit. Idempotent.
func (n *PassiveNode) Close() error {
	var err error
	n.closeOnce.Do(func() {
		close(n.closed)
		err = n.conn.Close()
	})
	return err
}

// --- read loop ---

func (n *PassiveNode) readLoop(ctx context.Context) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			_ = n.conn.Close()
			return
		case <-n.closed:
			return
		default:
		}
		// Short read deadline so we periodically check context cancellation;
		// the KRPC handler itself is stateless so losing a packet at shutdown
		// is harmless.
		_ = n.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		nb, src, err := n.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return // socket closed
		}
		// Copy: the bencode decoder retains sub-slices of the input buffer.
		data := append([]byte(nil), buf[:nb]...)
		go n.handlePacket(data, src)
	}
}

func (n *PassiveNode) handlePacket(data []byte, src *net.UDPAddr) {
	v, err := bencode.Decode(data)
	if err != nil {
		return
	}
	top, ok := bencode.AsDict(v)
	if !ok {
		return
	}
	// Opportunistic BEP 42 upgrade from any incoming packet that echoes our
	// external IP (rare for queries, but costs nothing to try).
	if ip := extractObservedIPv4(top); ip != nil {
		n.observeExternalIP(ip)
	}
	// Only queries need replies; drop responses ("r") and errors ("e").
	y, _ := bencode.DictString(top, "y")
	if y != "q" {
		return
	}
	tx, ok := bencode.DictBytes(top, "t")
	if !ok {
		return
	}
	q, _ := bencode.DictString(top, "q")
	args, _ := bencode.AsDict(top["a"])
	if args == nil {
		return
	}
	n.queriesRecv.Add(1)
	metrics.IncPassiveQuery()
	switch q {
	case "ping":
		n.replyPing(tx, src)
	case "find_node":
		n.replyFindNode(tx, src)
	case "get_peers":
		n.replyGetPeers(tx, src, args)
	case "announce_peer":
		n.handleAnnouncePeer(tx, src, args)
	}
}

// --- query handlers ---

func (n *PassiveNode) replyPing(tx []byte, src *net.UDPAddr) {
	n.writeResponse(tx, src, encodeIDOnlyResponse(tx, n.currentID()))
}

func (n *PassiveNode) replyFindNode(tx []byte, src *net.UDPAddr) {
	// Empty nodes list. Legal KRPC; a few querier implementations treat this
	// as a non-routing node and move on. We remain in their routing table
	// because they saw us respond — which is the only thing that matters.
	n.writeResponse(tx, src, encodeFindNodeResponse(tx, n.currentID()))
}

func (n *PassiveNode) replyGetPeers(tx []byte, src *net.UDPAddr, args map[string]any) {
	ih, ok := bencode.DictBytes(args, "info_hash")
	if !ok || len(ih) != IDLen {
		return
	}
	tok := n.issueToken(src.IP)
	n.writeResponse(tx, src, encodeGetPeersResponse(tx, n.currentID(), tok))
}

// handleAnnouncePeer validates the token and records the observation. We also
// record when the token is invalid — observing what clients announce is the
// whole point; strict token checking here would cost us data without protecting
// anyone, because the database is keyed on (infohash, peer) and the worst a
// liar can do is insert their own IP as "announcing", which is trivially true.
func (n *PassiveNode) handleAnnouncePeer(tx []byte, src *net.UDPAddr, args map[string]any) {
	ih, ok := bencode.DictBytes(args, "info_hash")
	if !ok || len(ih) != IDLen {
		return
	}
	peerIP := src.IP
	peerPort := src.Port
	if implied, _ := bencode.DictInt(args, "implied_port"); implied == 0 {
		if p, ok := bencode.DictInt(args, "port"); ok && p > 0 && p < 65536 {
			peerPort = int(p)
		}
	}
	if peerPort <= 0 || peerPort >= 65536 {
		return
	}
	if !usableIP(peerIP) {
		return
	}

	n.announcesRec.Add(1)
	metrics.IncPassiveAnnounce()
	// Always reply (echo our id); token check is advisory for observation.
	n.writeResponse(tx, src, encodeIDOnlyResponse(tx, n.currentID()))

	if n.opts.Recorder == nil {
		return
	}
	infohashHex := bytesToHex(ih)
	peer := fmt.Sprintf("%s:%d", peerIP.String(), peerPort)
	n.opts.Recorder.Record(infohashHex, peer)
}

// --- helpers: current id, BEP 42 upgrade ---

func (n *PassiveNode) currentID() NodeID {
	n.idMu.RLock()
	defer n.idMu.RUnlock()
	return n.selfID
}

func (n *PassiveNode) observeExternalIP(ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	n.idMu.RLock()
	same := n.observed.Equal(ip4)
	n.idMu.RUnlock()
	if same {
		return
	}
	newID, err := bep42NodeID(ip4)
	if err != nil {
		return
	}
	n.idMu.Lock()
	n.observed = append(net.IP(nil), ip4...)
	n.selfID = newID
	n.idMu.Unlock()
}

// --- token store ---

// rotateTokens refreshes the HMAC secret every PassiveOptions.TokenRotation.
// The previous secret is retained so a get_peers token issued just before
// rotation still validates an announce_peer that lands just after.
func (n *PassiveNode) rotateTokens(ctx context.Context) {
	ticker := time.NewTicker(n.opts.TokenRotation)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.closed:
			return
		case <-ticker.C:
		}
		var next [32]byte
		if _, err := rand.Read(next[:]); err != nil {
			continue
		}
		n.tokMu.Lock()
		n.prvSecret = n.curSecret
		n.curSecret = next
		n.hasPrv = true
		n.tokMu.Unlock()
	}
}

func (n *PassiveNode) issueToken(ip net.IP) []byte {
	n.tokMu.RLock()
	secret := n.curSecret
	n.tokMu.RUnlock()
	return makeToken(secret[:], ip)
}

// ValidateToken is currently unused in observation mode (see handleAnnouncePeer)
// but retained as the correctness gate for any future strict mode.
func (n *PassiveNode) validateToken(tok []byte, ip net.IP) bool { //nolint:unused
	if len(tok) != 8 {
		return false
	}
	n.tokMu.RLock()
	cur := n.curSecret
	prv := n.prvSecret
	hasPrv := n.hasPrv
	n.tokMu.RUnlock()
	if hmac.Equal(tok, makeToken(cur[:], ip)) {
		return true
	}
	if hasPrv && hmac.Equal(tok, makeToken(prv[:], ip)) {
		return true
	}
	return false
}

func makeToken(secret []byte, ip net.IP) []byte {
	mac := hmac.New(sha256.New, secret)
	if ip4 := ip.To4(); ip4 != nil {
		mac.Write(ip4)
	} else {
		mac.Write(ip.To16())
	}
	sum := mac.Sum(nil)
	return sum[:8]
}

// --- KRPC encoding ---
//
// We hand-roll minimal, fixed-shape encoders to stay allocation-light and
// avoid a full encoder dependency. All keys are written in lexicographic
// order as required by BEP 5.

func (n *PassiveNode) writeResponse(_ []byte, src *net.UDPAddr, payload []byte) {
	if payload == nil {
		return
	}
	_ = n.conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, _ = n.conn.WriteToUDP(payload, src)
}

// encodeIDOnlyResponse is used for ping and announce_peer replies: {"r":{"id":...}}.
func encodeIDOnlyResponse(tx []byte, id NodeID) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, "d1:rd2:id20:"...)
	buf = append(buf, id[:]...)
	buf = append(buf, 'e') // close r dict
	buf = appendBenchBytes(buf, "t", tx)
	buf = append(buf, "1:y1:re"...)
	return buf
}

// encodeFindNodeResponse returns an empty nodes bytestring: legal and tiny.
func encodeFindNodeResponse(tx []byte, id NodeID) []byte {
	buf := make([]byte, 0, 80)
	buf = append(buf, "d1:rd2:id20:"...)
	buf = append(buf, id[:]...)
	buf = append(buf, "5:nodes0:"...) // empty bytes
	buf = append(buf, 'e')
	buf = appendBenchBytes(buf, "t", tx)
	buf = append(buf, "1:y1:re"...)
	return buf
}

// encodeGetPeersResponse: reply with empty values list and our token. A future
// enhancement is to return peers we KNOW from our own passive cache, which
// would upgrade us from "sinkhole" to "useful node". For now: empty values.
// The querier still adds us to their routing table and may announce_peer.
func encodeGetPeersResponse(tx []byte, id NodeID, token []byte) []byte {
	buf := make([]byte, 0, 128)
	buf = append(buf, "d1:rd2:id20:"...)
	buf = append(buf, id[:]...)
	// lexicographic order inside r: id < nodes < token < values
	buf = append(buf, "5:nodes0:"...)
	buf = appendBenchBytes(buf, "token", token)
	buf = append(buf, "6:valuesle"...) // empty list of values
	buf = append(buf, 'e')             // close r
	buf = appendBenchBytes(buf, "t", tx)
	buf = append(buf, "1:y1:re"...)
	return buf
}

func appendBenchBytes(buf []byte, key string, val []byte) []byte {
	buf = append(buf, fmt.Sprintf("%d:", len(key))...)
	buf = append(buf, key...)
	buf = append(buf, fmt.Sprintf("%d:", len(val))...)
	buf = append(buf, val...)
	return buf
}

// bytesToHex is a tiny lower-case hex formatter that does not pull in
// encoding/hex just for 20 bytes on the hot path.
func bytesToHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i] = digits[c>>4]
		out[2*i+1] = digits[c&0x0f]
	}
	return string(out)
}

// Stats returns a snapshot of cumulative counters for observability.
func (n *PassiveNode) Stats() (queries, announces uint64) {
	return n.queriesRecv.Load(), n.announcesRec.Load()
}

// Keep validateToken compiled against the unused-symbol detector: this is
// the correctness gate we'll flip on when we harden announce_peer handling.
var _ = (*PassiveNode).validateToken
