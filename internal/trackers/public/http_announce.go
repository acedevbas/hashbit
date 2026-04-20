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
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

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

	// Per-request budget; same rationale as udpAnnounceBudget.
	httpAnnounceBudget = 5 * time.Second
)

// announceHTTP fans out BEP 3 /announce requests across all HTTP endpoints for
// every hash and merges per-hash results into `results` via max(). Matches the
// shape of announceUDP — one goroutine per (endpoint, hash), sem-bounded.
func announceHTTP(ctx context.Context, hc *httpclient.Client, endpoints []string, hashes []string,
	results map[string]trackers.Response, mu *sync.Mutex, sem chan struct{}, sink PeerSink) {

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

	health := newEndpointHealth()
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
				if health.Bad(endpoint) {
					return
				}
				reqCtx, cancel := context.WithTimeout(ctx, httpAnnounceBudget)
				partial, extractedPeers, ok := announceHTTPOne(reqCtx, hc, endpoint, hexHash, raw)
				cancel()
				if !ok {
					health.Mark(endpoint)
				}
				if sink != nil && len(extractedPeers) > 0 {
					for _, p := range extractedPeers {
						sink.Record(hexHash, p)
					}
				}
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
//
// Returns (partial, peers, ok). ok=false signals an endpoint-level failure
// and the caller should mark the endpoint dead for the remainder of the
// Scrape; nil partial with ok=true is just "tracker has no data on this
// hash". `peers` is the decoded "ip:port" list extracted from the BEP 23
// compact peer field, fed into the passive cache by the caller.
func announceHTTPOne(ctx context.Context, hc *httpclient.Client, announceURL, hexHash string, raw []byte) (map[string]trackers.Response, []string, bool) {
	out := make(map[string]trackers.Response)

	peerID, err := generatePeerID()
	if err != nil {
		return out, nil, true
	}
	key, err := generateHexKey(4)
	if err != nil {
		return out, nil, true
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
		return out, nil, false
	}
	v, err := bencode.Decode(body)
	if err != nil {
		return out, nil, false
	}
	top, ok := bencode.AsDict(v)
	if !ok {
		return out, nil, false
	}
	if _, failed := bencode.DictString(top, "failure reason"); failed {
		return out, nil, true // tracker is alive but rejected this specific request
	}

	seeds, _ := bencode.DictInt(top, "complete")
	leech, _ := bencode.DictInt(top, "incomplete")
	peerCount, extracted := extractAnnouncePeers(top)

	// Empty swarm per tracker — skip so we don't clobber a mirror with real data.
	if seeds == 0 && leech == 0 && peerCount == 0 {
		return out, extracted, true
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
	return out, extracted, true
}

// extractAnnouncePeers parses BEP 23 (compact v4) / BEP 7 (compact v6) /
// legacy dict-list peer fields and returns both the count and decoded
// "ip:port" strings. Legacy dict-list entries produce addresses too when
// they carry ip/port keys. Cross-call deduplication happens at the
// passive cache layer.
func extractAnnouncePeers(top map[string]any) (int32, []string) {
	var out []string
	if peers, ok := bencode.AsBytes(top["peers"]); ok {
		// BEP 23 compact form: 4 bytes IPv4 + 2 bytes port per peer.
		for i := 0; i+6 <= len(peers); i += 6 {
			if p := formatCompactPeer(peers[i : i+6]); p != "" {
				out = append(out, p)
			}
		}
	} else if peersList, ok := top["peers"].([]any); ok {
		// Legacy dict form — each entry is {ip: "...", port: N}. Rare in 2025
		// but cheap to parse, and some bencoded trackers still emit this.
		for _, e := range peersList {
			m, ok := bencode.AsDict(e)
			if !ok {
				continue
			}
			ipStr, _ := bencode.DictString(m, "ip")
			port, _ := bencode.DictInt(m, "port")
			if ipStr == "" || port <= 0 || port >= 65536 {
				continue
			}
			out = append(out, ipStr+":"+strconv.FormatInt(port, 10))
		}
	}
	if peers6, ok := bencode.AsBytes(top["peers6"]); ok {
		// BEP 7 compact IPv6: 16 bytes address + 2 bytes port per peer.
		for i := 0; i+18 <= len(peers6); i += 18 {
			if p := formatCompactPeer6(peers6[i : i+18]); p != "" {
				out = append(out, p)
			}
		}
	}
	return clip32(int64(len(out))), out
}

// formatCompactPeer6 decodes a BEP 7 compact IPv6 peer (16-byte addr +
// 2-byte BE port) into a "[addr]:port" string. Returns empty on a zero
// port (placeholder padding).
func formatCompactPeer6(b []byte) string {
	if len(b) != 18 {
		return ""
	}
	port := int(b[16])<<8 | int(b[17])
	if port == 0 {
		return ""
	}
	ip := net.IP(append([]byte(nil), b[:16]...))
	return "[" + ip.String() + "]:" + strconv.Itoa(port)
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
