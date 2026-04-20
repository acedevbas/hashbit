// UDP tracker protocol (BEP 15) implementation.
//
// Connect:
//
//	[ protocol_id u64=0x41727101980 | action u32=0 | transaction_id u32 ]
//	response: [ action u32=0 | transaction_id u32 | connection_id u64 ]
//
// Scrape:
//
//	[ connection_id u64 | action u32=2 | transaction_id u32 | info_hash 20*N ]
//	response: [ action u32=2 | transaction_id u32 | { seeders u32, completed u32, leechers u32 } * N ]
//
// Error:
//
//	response: [ action u32=3 | transaction_id u32 | ascii message ]
//
// Retransmission budget is kept intentionally small — this code runs in a large
// fan-out where a stuck tracker would otherwise hold the whole batch; one shot
// with short timeouts is better than BEP 15's recommended exponential backoff.
package public

import (
	"context"
	"crypto/rand"
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
	udpProtocolID uint64 = 0x41727101980
	udpActConnect uint32 = 0
	udpActScrape  uint32 = 2
	udpActError   uint32 = 3

	udpConnectTimeout = 3 * time.Second
	udpScrapeTimeout  = 5 * time.Second

	// Per-endpoint scrape budget — one UDP connect + up to (hashes/70) chunks.
	// With 500 hashes that's 8 chunks × 5s read = up to 40s if a tracker is slow;
	// the budget caps the tail at a reasonable value so one dawdling tracker
	// cannot bleed into the next tick.
	udpScrapeEndpointBudget = 10 * time.Second
)

// scrapeUDP fans out across UDP endpoints in parallel (capped by sem) and merges
// per-hash results into `results` via max().
func scrapeUDP(ctx context.Context, endpoints []string, hashes []string,
	results map[string]trackers.Response, mu *sync.Mutex, sem chan struct{}) {

	if len(endpoints) == 0 || len(hashes) == 0 {
		return
	}

	// Pre-decode hashes once — every endpoint needs the same raw bytes.
	raw := make([][20]byte, 0, len(hashes))
	hexHashes := make([]string, 0, len(hashes))
	for _, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 20 {
			continue
		}
		var arr [20]byte
		copy(arr[:], b)
		raw = append(raw, arr)
		hexHashes = append(hexHashes, h)
	}
	if len(raw) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, ep := range endpoints {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			reqCtx, cancel := context.WithTimeout(ctx, udpScrapeEndpointBudget)
			partial := scrapeUDPOne(reqCtx, endpoint, hexHashes, raw)
			cancel()
			if len(partial) == 0 {
				return
			}
			mu.Lock()
			mergeInto(results, partial)
			mu.Unlock()
		}(ep)
	}
	wg.Wait()
}

// scrapeUDPOne opens a single UDP socket to endpoint, performs connect + one or
// more scrape requests (chunked to MaxUDPHashesPerRequest), and returns results
// keyed by hex-infohash. A dead endpoint returns an empty map, not an error —
// callers treat public trackers as best-effort.
func scrapeUDPOne(ctx context.Context, endpoint string, hexHashes []string, raw [][20]byte) map[string]trackers.Response {
	out := make(map[string]trackers.Response)

	host := strings.TrimPrefix(endpoint, "udp://")
	// Strip any trailing path (e.g. "/announce") — UDP tracker protocol ignores it.
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

	// Propagate ctx deadline as an overall cap on the UDP flow.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	connID, err := udpConnect(conn)
	if err != nil {
		return out
	}

	// Split hashes into MTU-safe chunks.
	for i := 0; i < len(raw); i += MaxUDPHashesPerRequest {
		if ctx.Err() != nil {
			return out
		}
		end := i + MaxUDPHashesPerRequest
		if end > len(raw) {
			end = len(raw)
		}
		udpScrapeChunk(conn, connID, hexHashes[i:end], raw[i:end], out)
	}
	return out
}

func udpConnect(conn *net.UDPConn) (uint64, error) {
	txid, err := randomUint32()
	if err != nil {
		return 0, err
	}
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], udpProtocolID)
	binary.BigEndian.PutUint32(buf[8:12], udpActConnect)
	binary.BigEndian.PutUint32(buf[12:16], txid)

	_ = conn.SetWriteDeadline(time.Now().Add(udpConnectTimeout))
	if _, err := conn.Write(buf); err != nil {
		return 0, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(udpConnectTimeout))

	resp := make([]byte, 16)
	n, err := conn.Read(resp)
	if err != nil {
		return 0, err
	}
	if n < 16 {
		return 0, fmt.Errorf("short connect response: %d bytes", n)
	}
	action := binary.BigEndian.Uint32(resp[0:4])
	gotTxID := binary.BigEndian.Uint32(resp[4:8])
	if action != udpActConnect || gotTxID != txid {
		return 0, fmt.Errorf("bad connect response: action=%d txid=%d", action, gotTxID)
	}
	return binary.BigEndian.Uint64(resp[8:16]), nil
}

func udpScrapeChunk(conn *net.UDPConn, connID uint64, hexHashes []string, raw [][20]byte, out map[string]trackers.Response) {
	if len(raw) == 0 {
		return
	}
	txid, err := randomUint32()
	if err != nil {
		return
	}

	req := make([]byte, 16+20*len(raw))
	binary.BigEndian.PutUint64(req[0:8], connID)
	binary.BigEndian.PutUint32(req[8:12], udpActScrape)
	binary.BigEndian.PutUint32(req[12:16], txid)
	for i, h := range raw {
		copy(req[16+20*i:16+20*(i+1)], h[:])
	}

	_ = conn.SetWriteDeadline(time.Now().Add(udpScrapeTimeout))
	if _, err := conn.Write(req); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(udpScrapeTimeout))

	// Max response size = 8 (header) + 12 * N. Add slack for error messages.
	respBuf := make([]byte, 8+12*len(raw)+256)
	n, err := conn.Read(respBuf)
	if err != nil {
		return
	}
	if n < 8 {
		return
	}
	resp := respBuf[:n]
	action := binary.BigEndian.Uint32(resp[0:4])
	gotTxID := binary.BigEndian.Uint32(resp[4:8])
	if gotTxID != txid {
		return // stale/out-of-order datagram; trust transaction_id
	}
	if action == udpActError {
		return
	}
	if action != udpActScrape {
		return
	}
	// Each entry: seeders, completed, leechers (uint32 BE).
	const entrySize = 12
	entries := (n - 8) / entrySize
	if entries > len(raw) {
		entries = len(raw)
	}
	for i := 0; i < entries; i++ {
		off := 8 + entrySize*i
		seeds := binary.BigEndian.Uint32(resp[off : off+4])
		comp := binary.BigEndian.Uint32(resp[off+4 : off+8])
		leech := binary.BigEndian.Uint32(resp[off+8 : off+12])
		if seeds == 0 && comp == 0 && leech == 0 {
			continue // tracker doesn't know this hash (or dead torrent) — skip
		}
		out[hexHashes[i]] = trackers.Response{
			Status: trackers.StatusOK,
			Result: trackers.ScrapeResult{
				Seeders:   clip32u(seeds),
				Leechers:  clip32u(leech),
				Completed: clip32u(comp),
				PeerCount: -1,
			},
		}
	}
}

func randomUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func clip32u(n uint32) int32 {
	const max uint32 = 0x7FFFFFFF
	if n > max {
		return int32(max)
	}
	return int32(n)
}
