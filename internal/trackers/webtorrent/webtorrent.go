package webtorrent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/acedevbas/hashbit/internal/trackers"
)

// Per-connection timeouts. The dial budget is generous because TLS + WS
// handshake through some of these servers routinely takes 2-3s from EU/RU
// networks. Read budget is short because after the handshake the server
// either answers within a second or starts spraying WebRTC offers we ignore.
const (
	dialTimeout = 8 * time.Second
	readTimeout = 5 * time.Second
)

// Scraper probes WebTorrent WSS endpoints for swarm counts per infohash.
// Each (hash, endpoint) pair is an independent WebSocket dial; results are
// merged with max() across endpoints, mirroring the public scraper shape.
type Scraper struct {
	endpoints   []string
	concurrency int
}

// New returns a scraper with the bundled endpoint list. concurrency caps how
// many simultaneous WS dials are in flight across the whole Scrape call.
func New(concurrency int) *Scraper {
	if concurrency <= 0 {
		concurrency = 8
	}
	return &Scraper{
		endpoints:   Endpoints,
		concurrency: concurrency,
	}
}

// Scrape fans out every hash to every endpoint, merges counts via max, and
// returns one Response per input hash. Hashes that no endpoint knew about
// stay as StatusNotFound.
func (s *Scraper) Scrape(ctx context.Context, hashes []string) map[string]trackers.Response {
	result := make(map[string]trackers.Response, len(hashes))
	for _, h := range hashes {
		result[h] = trackers.Response{Status: trackers.StatusNotFound, Result: trackers.Unknown()}
	}
	if len(hashes) == 0 || len(s.endpoints) == 0 {
		return result
	}

	sem := make(chan struct{}, s.concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, h := range hashes {
		for _, ep := range s.endpoints {
			wg.Add(1)
			go func(hash, endpoint string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				seeders, leechers, ok := announceOne(ctx, endpoint, hash)
				if !ok {
					return
				}
				mu.Lock()
				mergeMax(result, hash, seeders, leechers)
				mu.Unlock()
			}(h, ep)
		}
	}
	wg.Wait()
	return result
}

// mergeMax updates result[hash] with the larger of (existing, incoming)
// per-field counts and flips Status to OK on first non-trivial observation.
func mergeMax(result map[string]trackers.Response, hash string, seeders, leechers int32) {
	prev := result[hash]
	prev.Status = trackers.StatusOK
	prev.Err = ""
	if seeders > prev.Result.Seeders {
		prev.Result.Seeders = seeders
	}
	if leechers > prev.Result.Leechers {
		prev.Result.Leechers = leechers
	}
	result[hash] = prev
}

// announceOne opens one WebSocket to endpoint, sends an announce for hexHash,
// and returns (seeders, leechers, true) on the first matching-info_hash reply.
// Returns ok=false on any error or timeout — we don't want to pollute the
// aggregate with zeros from endpoints that simply didn't respond.
//
// The protocol quirk that makes this non-trivial: info_hash and peer_id are
// 20 raw bytes that WebTorrent encodes as JSON strings in Latin-1 — each byte
// becomes one Unicode code point in [0, 255]. See encodeLatin1.
func announceOne(ctx context.Context, endpoint, hexHash string) (int32, int32, bool) {
	raw, err := hex.DecodeString(hexHash)
	if err != nil || len(raw) != 20 {
		return 0, 0, false
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	defer cancelDial()

	conn, _, err := websocket.Dial(dialCtx, endpoint, nil)
	if err != nil {
		return 0, 0, false
	}
	// CloseNow bypasses the WS close handshake — we don't care about a graceful
	// shutdown, just releasing the socket.
	defer func() { _ = conn.CloseNow() }()

	// A single announce is small but WebRTC offer frames piggyback on this
	// connection from peers being introduced to us. 1 MiB protects against a
	// flood of unsolicited offers while leaving plenty of room for a normal
	// announce reply (< 1 KiB).
	conn.SetReadLimit(1 << 20)

	peerID, err := randomPeerID()
	if err != nil {
		return 0, 0, false
	}

	announce := map[string]any{
		"action":     "announce",
		"info_hash":  encodeLatin1(raw),
		"peer_id":    encodeLatin1(peerID),
		"numwant":    50,
		"uploaded":   0,
		"downloaded": 0,
		"event":      "started",
	}
	payload, err := json.Marshal(announce)
	if err != nil {
		return 0, 0, false
	}

	writeCtx, cancelWrite := context.WithTimeout(ctx, readTimeout)
	defer cancelWrite()
	if err := conn.Write(writeCtx, websocket.MessageText, payload); err != nil {
		return 0, 0, false
	}

	readCtx, cancelRead := context.WithTimeout(ctx, readTimeout)
	defer cancelRead()
	return readMatchingReply(readCtx, conn, raw)
}

// readMatchingReply loops over frames until one arrives whose info_hash
// matches `want` and carries swarm counts. Non-announce frames (offer, error
// objects, answer) and announces for other infohashes are skipped — some
// servers multiplex replies for peers we are indirectly introduced to.
func readMatchingReply(ctx context.Context, conn *websocket.Conn, want []byte) (int32, int32, bool) {
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			// io.EOF or context deadline: endpoint simply didn't answer us.
			if errors.Is(err, io.EOF) || errors.Is(err, context.DeadlineExceeded) {
				return 0, 0, false
			}
			return 0, 0, false
		}

		var msg struct {
			Action     string          `json:"action"`
			InfoHash   string          `json:"info_hash"`
			Complete   json.RawMessage `json:"complete"`
			Incomplete json.RawMessage `json:"incomplete"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.Action != "" && msg.Action != "announce" {
			continue
		}
		if !latin1Equal(msg.InfoHash, want) {
			continue
		}
		complete, haveC := parseCount(msg.Complete)
		incomplete, haveI := parseCount(msg.Incomplete)
		if !haveC && !haveI {
			// Right hash, wrong frame type (e.g. server ack without counts).
			continue
		}
		// Self-echo compensation: we announced event=started as a "leecher"
		// (left>0 implied) so every reply includes ourselves in `incomplete`.
		// Production DB shows 100 % of observed rows have leechers≥1 even on
		// dead hashes — that's us. Subtract 1 to recover the real leecher count.
		// Seeders (`complete`) do not include us since we didn't claim completed.
		if incomplete > 0 {
			incomplete--
		}
		return clip32(complete), clip32(incomplete), true
	}
}

// encodeLatin1 maps each byte 0-255 to a single rune of the same value. This
// is the JSON encoding WebTorrent trackers expect: bytes above 0x7F appear as
// `\u00XX` escapes, not as UTF-8 sequences. A naive `string(raw)` would work
// for ASCII-range bytes only; high bytes become the U+FFFD replacement rune
// once they're interpreted as UTF-8 by json.Marshal.
func encodeLatin1(raw []byte) string {
	runes := make([]rune, len(raw))
	for i, b := range raw {
		runes[i] = rune(b)
	}
	return string(runes)
}

// latin1Equal is the inverse check: true iff the Latin-1 decode of s equals
// raw. We can't just compare string(raw) to s because of the UTF-8/Latin-1
// asymmetry described on encodeLatin1.
func latin1Equal(s string, raw []byte) bool {
	runes := []rune(s)
	if len(runes) != len(raw) {
		return false
	}
	for i, r := range runes {
		if r < 0 || r > 255 || byte(r) != raw[i] {
			return false
		}
	}
	return true
}

// parseCount accepts an integer or a JSON null. Some trackers omit one of the
// fields entirely (e.g. send only `complete`), so a missing value is not an
// error — we just mark that field as not observed.
func parseCount(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false
	}
	if n < 0 {
		return 0, false
	}
	return n, true
}

// randomPeerID fabricates a 20-byte peer id. WebTorrent clients usually
// prefix with "-WW" + version bytes, but the trackers we scrape don't
// validate the shape — they just echo it back — so a fully random id keeps
// us indistinguishable across scrapes.
func randomPeerID() ([]byte, error) {
	id := make([]byte, 20)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return id, nil
}

func clip32(n int) int32 {
	const maxInt32 = int32(^uint32(0) >> 1)
	if n < 0 {
		return 0
	}
	if n > int(maxInt32) {
		return maxInt32
	}
	return int32(n)
}
