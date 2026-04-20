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
)

// announceUDP runs BEP 15 announces in parallel across all UDP endpoints for
// every hash, harvesting peer lists + authoritative seeders/leechers counts.
// Merges into `results` via max(). Unlike scrape (multi-hash per request),
// announce is single-hash, so this does len(hashes) * len(endpoints) roundtrips.
func announceUDP(ctx context.Context, endpoints []string, hashes []string,
	results map[string]trackers.Response, mu *sync.Mutex, sem chan struct{}) {

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
				partial := announceUDPOne(ctx, endpoint, hex, raw)
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

func announceUDPOne(ctx context.Context, endpoint, hexHash string, raw [20]byte) map[string]trackers.Response {
	out := make(map[string]trackers.Response)

	host := strings.TrimPrefix(endpoint, "udp://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	addr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return out
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return out
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	connID, err := udpConnect(conn)
	if err != nil {
		return out
	}

	txid, err := randomUint32()
	if err != nil {
		return out
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
		return out
	}
	_ = conn.SetReadDeadline(time.Now().Add(udpScrapeTimeout))

	// Response: 20 header + 6*N peer bytes. Cap at MTU-ish for safety.
	buf := make([]byte, 20+6*200+64)
	n, err := conn.Read(buf)
	if err != nil {
		return out
	}
	if n < 20 {
		return out
	}
	resp := buf[:n]
	action := binary.BigEndian.Uint32(resp[0:4])
	gotTxID := binary.BigEndian.Uint32(resp[4:8])
	if gotTxID != txid {
		return out
	}
	if action == udpActError {
		return out
	}
	if action != udpActAnnounce {
		return out
	}
	// interval at resp[8:12] — ignored; we're not rescheduling by tracker advice.
	leechers := binary.BigEndian.Uint32(resp[12:16])
	seeders := binary.BigEndian.Uint32(resp[16:20])

	// Count peer entries (6 bytes each). Used as peer_count signal.
	peers := resp[20:]
	peerCount := int32(len(peers) / 6)

	// If swarm is empty by tracker account, treat as not-found to avoid
	// wiping smarter sources' data. Otherwise record this tracker's view.
	if seeders == 0 && leechers == 0 && peerCount == 0 {
		return out
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
	return out
}

// formatCompactPeer is unused directly today — the peer list is counted but
// not further fanned out — retained here as a hook for future work that
// might want to feed discovered peers back into btprobe / DHT fingerprint.
func formatCompactPeer(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	ip := net.IPv4(b[0], b[1], b[2], b[3])
	port := binary.BigEndian.Uint16(b[4:6])
	return fmt.Sprintf("%s:%d", ip.To4(), port)
}

var _ = formatCompactPeer // avoid unused-symbol warnings in Go vet
