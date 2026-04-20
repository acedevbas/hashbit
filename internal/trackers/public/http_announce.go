// HTTP tracker announce (BEP 3 /announce).
//
// Unlike scrape (counts-only, multi-hash per request), announce is a per-hash
// request that returns BOTH seeders/leechers counts AND a compact peer list
// of up to ~200 peers. Running alongside UDP announce ~doubles peer-visibility
// at the price of one HTTP round-trip per (hash, endpoint).
//
// We convert the endpoint's /scrape URL back to /announce, then synthesize a
// plausible BT client request. `left` is a non-zero constant — trackers
// reject "seeding" announces from peers with 0 uploaded. Response is the
// standard BEP 3 + BEP 23 bencoded dict (complete/incomplete/peers/peers6).
package public

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/acedevbas/hashbit/internal/bencode"
	"github.com/acedevbas/hashbit/internal/httpclient"
	"github.com/acedevbas/hashbit/internal/trackers"
)

const (
	httpAnnouncePort    = 6881
	httpAnnounceNumWant = 200
	// httpAnnounceLeft is sent as the `left` query param. Zero would signal
	// "seeding", which some trackers refuse from peers with 0 uploaded.
	httpAnnounceLeft = 16777216 // 16 MiB — arbitrary non-zero "still downloading"
)

// announceHTTP fans out BEP 3 /announce requests across all HTTP endpoints for
// every hash and merges per-hash results into `results` via max(). Matches the
// shape of announceUDP — one goroutine per (endpoint, hash), sem-bounded.
func announceHTTP(ctx context.Context, hc *httpclient.Client, endpoints []string, hashes []string,
	results map[string]trackers.Response, mu *sync.Mutex, sem chan struct{}) {

	if len(endpoints) == 0 || len(hashes) == 0 {
		return
	}

	// Pre-decode once — same raw bytes go to every endpoint.
	rawByHash := make(map[string][]byte, len(hashes))
	for _, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 20 {
			continue
		}
		rawByHash[h] = b
	}
	if len(rawByHash) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, ep := range endpoints {
		announceURL := scrapeToAnnounceURL(ep)
		if announceURL == "" {
			continue
		}
		for h, raw := range rawByHash {
			wg.Add(1)
			go func(endpoint, hexHash string, raw []byte) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				partial := announceHTTPOne(ctx, hc, endpoint, hexHash, raw)
				if len(partial) == 0 {
					return
				}
				mu.Lock()
				mergeInto(results, partial)
				mu.Unlock()
			}(announceURL, h, raw)
		}
	}
	wg.Wait()
}

// scrapeToAnnounceURL converts the tracker's scrape URL back to its announce
// URL. BEP 48 conventions: swap the LAST "/scrape" occurrence with "/announce"
// so we don't accidentally rewrite a host containing "scrape" in its name.
func scrapeToAnnounceURL(scrapeURL string) string {
	idx := strings.LastIndex(scrapeURL, "/scrape")
	if idx < 0 {
		return "" // not a scrape URL shape we understand; skip
	}
	return scrapeURL[:idx] + "/announce" + scrapeURL[idx+len("/scrape"):]
}

// announceHTTPOne issues one BEP 3 announce. event=started is intentionally
// omitted — we re-announce the same hashes every scrape tick, and "started"
// on each call would tip trackers off to rate-limit us.
func announceHTTPOne(ctx context.Context, hc *httpclient.Client, announceURL, hexHash string, raw []byte) map[string]trackers.Response {
	out := make(map[string]trackers.Response)

	peerID, err := generatePeerID()
	if err != nil {
		return out
	}
	key, err := generateHexKey(4)
	if err != nil {
		return out
	}

	// Build query string. url.Values would alphabetize keys; order doesn't matter
	// to trackers, but we avoid the allocation by building manually.
	var sb strings.Builder
	sb.WriteString(announceURL)
	if strings.Contains(announceURL, "?") {
		sb.WriteByte('&')
	} else {
		sb.WriteByte('?')
	}
	sb.WriteString("info_hash=")
	sb.WriteString(url.QueryEscape(string(raw)))
	sb.WriteString("&peer_id=")
	sb.WriteString(url.QueryEscape(peerID))
	sb.WriteString("&port=")
	sb.WriteString(strconv.Itoa(httpAnnouncePort))
	sb.WriteString("&uploaded=0&downloaded=0&left=")
	sb.WriteString(strconv.Itoa(httpAnnounceLeft))
	sb.WriteString("&compact=1&numwant=")
	sb.WriteString(strconv.Itoa(httpAnnounceNumWant))
	sb.WriteString("&key=")
	sb.WriteString(key)

	body, _, err := hc.Get(ctx, sb.String())
	if err != nil {
		return out
	}
	v, err := bencode.Decode(body)
	if err != nil {
		return out
	}
	top, ok := bencode.AsDict(v)
	if !ok {
		return out
	}
	if _, failed := bencode.DictString(top, "failure reason"); failed {
		return out // tracker rejected the request; don't merge anything
	}

	seeds, _ := bencode.DictInt(top, "complete")
	leech, _ := bencode.DictInt(top, "incomplete")
	peerCount := countAnnouncePeers(top)

	// Empty swarm per tracker — skip so we don't clobber a mirror with real data.
	if seeds == 0 && leech == 0 && peerCount == 0 {
		return out
	}
	out[hexHash] = trackers.Response{
		Status: trackers.StatusOK,
		Result: trackers.ScrapeResult{
			Seeders:   clip32(seeds),
			Leechers:  clip32(leech),
			Completed: -1, // announce doesn't return downloaded count
			PeerCount: peerCount,
		},
	}
	return out
}

// countAnnouncePeers returns the number of distinct peer entries found in the
// "peers" (compact 6-byte or dict-list) and "peers6" (compact 18-byte) fields.
// No cross-call deduplication — mergeInto takes max() across endpoints, which
// is good enough signal for the scheduler.
func countAnnouncePeers(top map[string]any) int32 {
	var count int
	if peers, ok := bencode.AsBytes(top["peers"]); ok {
		// BEP 23 compact form: 4 bytes IPv4 + 2 bytes port per peer.
		count += len(peers) / 6
	} else if peersList, ok := top["peers"].([]any); ok {
		// Legacy dict form — each entry is {ip: "...", port: N}. Rare in 2025.
		count += len(peersList)
	}
	if peers6, ok := bencode.AsBytes(top["peers6"]); ok {
		// BEP 7 compact IPv6: 16 bytes address + 2 bytes port per peer.
		count += len(peers6) / 18
	}
	return clip32(int64(count))
}

// generatePeerID produces a 20-byte peer_id using the Azureus "-UT3550-" prefix
// to mimic a mainstream client. The trailing 12 bytes are freshly random per
// call: reusing a peer_id across announces to the same tracker looks like a
// bot and invites rate-limiting, so we never cache it.
func generatePeerID() (string, error) {
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return "-UT3550-" + string(suffix[:]), nil
}

// generateHexKey returns a random hex-encoded key, used as the `key` query
// param. Trackers use this to correlate announces from a client across IP
// changes — for us it's just entropy to look like a real client.
func generateHexKey(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
