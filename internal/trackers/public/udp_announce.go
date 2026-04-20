// UDP tracker announce (BEP 15 action=1).
//
// Announce is the tracker's primary endpoint — every real BT client calls it
// every ~30 min — and unlike scrape it returns not only seeders/leechers
// counts but also a compact list of up to ~200 peers. Running announce in
// parallel to the usual multi-hash scrape ≈ 10× peer visibility at the cost
// of one UDP round-trip per (hash, tracker) instead of one per tracker.
//
// Request layout (98 bytes):
//
//	[connection_id u64 | action=1 u32 | tx_id u32 | info_hash 20 |
//	 peer_id 20 | downloaded u64 | left u64 | uploaded u64 |
//	 event u32 | ip u32 | key u32 | num_want i32 | port u16 |
//	 (optional) extensions]
//
// Response layout (20 + 6*N bytes):
//
//	[action=1 u32 | tx_id u32 | interval u32 | leechers u32 | seeders u32 |
//	 {ip u32, port u16}*N]
//
// Since we're not actually serving BT content, our reported downloaded /
// uploaded / left are zero and our advertised port is a bogon — no client
// will contact us back, we're strictly consuming the peer list.
package public

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/acedevbas/hashbit/internal/trackers"
)

const (
	udpActAnnounce uint32 = 1
	udpEventNone   uint32 = 0
	udpNumWant     int32  = 200
	udpFakePort    uint16 = 6881

	// Per-request budget for one UDP announce. Announce is single-hash, so this
	// caps the tail cost of a slow endpoint per (hash, endpoint) pair. Was
	// previously driven off the outer Scrape deadline, which meant one stuck
	// endpoint × len(hashes) goroutines could hold concurrency slots for the
	// entire outer budget and stall the whole fan-out.
	udpAnnounceBudget = 4 * time.Second
)

// announceUDP runs BEP 15 announces in parallel across all UDP endpoints for
// every hash, harvesting peer lists + authoritative seeders/leechers counts.
// Merges into `results` via max(). Unlike scrape (multi-hash per request),
// announce is single-hash, so this does len(hashes) * len(endpoints) roundtrips.
//
// Each (endpoint, hash) gets its own per-request context with a short timeout
// so one stuck endpoint cannot stall the fan-out. An endpoint-level health
// breaker additionally skips further hashes on an endpoint once any one of
// its requests fails — useful when a tracker is down and would otherwise
// burn len(hashes) × per-request budget on dead air.
func announceUDP(ctx context.Context, endpoints []string, hashes []string,
	results map[string]trackers.Response, mu *sync.Mutex, sem chan struct{}, sink PeerSink) {

	if len(endpoints) == 0 || len(hashes) == 0 {
		return
	}

	// Pre-decode once.
	rawByHash := make(map[string][20]byte, len(hashes))
	for _, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 20 {
			continue
		}
		var arr [20]byte
		copy(arr[:], b)
		rawByHash[h] = arr
	}
	if len(rawByHash) == 0 {
		return
	}

	health := newEndpointHealth()
	var wg sync.WaitGroup
	for _, ep := range endpoints {
		for h, raw := range rawByHash {
			wg.Add(1)
			go func(endpoint, hex string, raw [20]byte) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				if health.Bad(endpoint) {
					return
				}
				reqCtx, cancel := context.WithTimeout(ctx, udpAnnounceBudget)
				partial, extractedPeers, ok := announceUDPOne(reqCtx, endpoint, hex, raw)
				cancel()
				if !ok {
					health.Mark(endpoint)
				}
				// Funnel every observed peer into the passive-cache sink
				// even when the partial map is empty (tracker returned
				// peers but the counts were zero — rare, but still useful
				// addresses). Non-blocking by contract of PeerSink.
				if sink != nil && len(extractedPeers) > 0 {
					for _, p := range extractedPeers {
						sink.Record(hex, p)
					}
				}
				if len(partial) == 0 {
					return
				}
				mu.Lock()
				mergeInto(results, partial)
				mu.Unlock()
			}(ep, h, raw)
		}
	}
	wg.Wait()
}

// announceUDPOne returns the partial result map, the extracted peer list
// (compact 6-byte entries decoded to "ip:port" strings), and a bool
// indicating whether the endpoint is healthy. ok=false signals the caller
// to mark the endpoint dead for the remainder of the Scrape. A nil result
// with ok=true means the tracker simply didn't know about this hash
// (empty swarm), not that it's broken.
func announceUDPOne(ctx context.Context, endpoint, hexHash string, raw [20]byte) (map[string]trackers.Response, []string, bool) {
	out := make(map[string]trackers.Response)

	host := strings.TrimPrefix(endpoint, "udp://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	addr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return out, nil, false
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return out, nil, false
	}
	defer conn.Close()
	// Drive both Read/Write deadlines off the inner ctx so one stuck endpoint
	// cannot outlast the per-request budget.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	connID, err := udpConnect(conn)
	if err != nil {
		return out, nil, false
	}

	txid, err := randomUint32()
	if err != nil {
		return out, nil, true
	}

	// BEP 15 announce request layout — 98 bytes total, no trailing extensions:
	//   [0..7]   connection_id u64
	//   [8..11]  action=1 u32
	//   [12..15] transaction_id u32
	//   [16..35] info_hash 20
	//   [36..55] peer_id 20
	//   [56..63] downloaded u64
	//   [64..71] left u64
	//   [72..79] uploaded u64
	//   [80..83] event u32
	//   [84..87] ip u32 (0 → tracker uses sender's src)
	//   [88..91] key u32
	//   [92..95] num_want i32
	//   [96..97] port u16
	req := make([]byte, 98)
	binary.BigEndian.PutUint64(req[0:8], connID)
	binary.BigEndian.PutUint32(req[8:12], udpActAnnounce)
	binary.BigEndian.PutUint32(req[12:16], txid)
	copy(req[16:36], raw[:])
	// peer_id: BEP 20 style "-UT3550-" + 12 bytes tx-derived pseudo-random.
	copy(req[36:44], "-UT3550-")
	binary.BigEndian.PutUint32(req[44:48], txid)
	binary.BigEndian.PutUint32(req[48:52], ^txid) // fill rest of 20-byte peer_id
	binary.BigEndian.PutUint32(req[52:56], txid^0xCAFEBABE)
	// [56..79] downloaded/left/uploaded — all zero; already zeroed by make().
	binary.BigEndian.PutUint32(req[80:84], udpEventNone)
	// [84..87] ip=0 → tracker uses src IP (already zero)
	binary.BigEndian.PutUint32(req[88:92], txid) // key
	binary.BigEndian.PutUint32(req[92:96], uint32(udpNumWant))
	binary.BigEndian.PutUint16(req[96:98], udpFakePort)

	_ = conn.SetWriteDeadline(time.Now().Add(udpScrapeTimeout))
	if _, err := conn.Write(req); err != nil {
		return out, nil, false
	}
	_ = conn.SetReadDeadline(time.Now().Add(udpScrapeTimeout))

	// Response: 20 header + 6*N peer bytes. Cap at MTU-ish for safety.
	buf := make([]byte, 20+6*200+64)
	n, err := conn.Read(buf)
	if err != nil {
		return out, nil, false
	}
	if n < 20 {
		return out, nil, false
	}
	resp := buf[:n]
	action := binary.BigEndian.Uint32(resp[0:4])
	gotTxID := binary.BigEndian.Uint32(resp[4:8])
	if gotTxID != txid {
		return out, nil, false
	}
	if action == udpActError {
		return out, nil, true // tracker is alive, just didn't like us — do not mark dead
	}
	if action != udpActAnnounce {
		return out, nil, false
	}
	// interval at resp[8:12] — ignored; we're not rescheduling by tracker advice.
	leechers := binary.BigEndian.Uint32(resp[12:16])
	seeders := binary.BigEndian.Uint32(resp[16:20])

	// Decode peer entries (6 bytes each). Used as peer_count signal AND as
	// raw addresses that flow into the passive cache sink.
	peers := resp[20:]
	peerCount := int32(len(peers) / 6)
	extracted := make([]string, 0, int(peerCount))
	for i := 0; i+6 <= len(peers); i += 6 {
		if p := formatCompactPeer(peers[i : i+6]); p != "" {
			extracted = append(extracted, p)
		}
	}

	// If swarm is empty by tracker account, treat as not-found to avoid
	// wiping smarter sources' data. Otherwise record this tracker's view.
	if seeders == 0 && leechers == 0 && peerCount == 0 {
		return out, extracted, true
	}
	out[hexHash] = trackers.Response{
		Status: trackers.StatusOK,
		Result: trackers.ScrapeResult{
			Seeders:   clip32u(seeders),
			Leechers:  clip32u(leechers),
			Completed: -1,
			PeerCount: peerCount,
		},
	}
	return out, extracted, true
}

// formatCompactPeer decodes a 6-byte BEP 23 compact peer record
// (4-byte IPv4 + 2-byte BE port) into a dial-ready "ip:port" string.
// Returns empty on a zero port — those are placeholders that some
// trackers pad the end of an announce response with.
func formatCompactPeer(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	port := binary.BigEndian.Uint16(b[4:6])
	if port == 0 {
		return ""
	}
	ip := net.IPv4(b[0], b[1], b[2], b[3])
	return fmt.Sprintf("%s:%d", ip.To4(), port)
}
