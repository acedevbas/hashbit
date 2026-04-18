// Package rutracker implements announce-based peer counting for Rutracker.
// Rutracker does not provide seeder/leecher counts in responses (likely anti-scrape).
// Instead, it returns a peer list (compact format). We count entries and subtract 1
// to account for "self-echo" — Rutracker includes our own peer_id in the returned list.
package rutracker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/acedevbas/hashbit/internal/bencode"
	"github.com/acedevbas/hashbit/internal/httpclient"
	"github.com/acedevbas/hashbit/internal/trackers"
)

const Endpoint = "http://bt2.t-ru.org/ann"

// NumWant is the upper cap on peers we'd like returned. Rutracker honors up to ~200.
const NumWant = 200

type Scraper struct {
	http *httpclient.Client
}

func New(hc *httpclient.Client) *Scraper { return &Scraper{http: hc} }

func (s *Scraper) Scrape(ctx context.Context, hashes []string) map[string]trackers.Response {
	out := make(map[string]trackers.Response, len(hashes))
	for _, h := range hashes {
		out[h] = s.scrapeOne(ctx, h)
	}
	return out
}

func (s *Scraper) scrapeOne(ctx context.Context, hash string) trackers.Response {
	raw, err := hex.DecodeString(hash)
	if err != nil || len(raw) != 20 {
		return trackers.Response{Status: trackers.StatusError, Result: trackers.Unknown(), Err: "bad hash"}
	}

	peerID := make([]byte, 20)
	copy(peerID, "-UT3550-")
	_, _ = rand.Read(peerID[8:])

	q := url.Values{}
	q.Set("info_hash", string(raw))
	q.Set("peer_id", string(peerID))
	q.Set("port", "6881")
	q.Set("uploaded", "0")
	q.Set("downloaded", "0")
	q.Set("left", "16777216") // pretend we're leeching so tracker gives us peers
	q.Set("numwant", intStr(NumWant))
	q.Set("compact", "1")
	q.Set("no_peer_id", "1")

	body, _, err := s.http.Get(ctx, Endpoint+"?"+q.Encode())
	if err != nil {
		return trackers.Response{Status: trackers.StatusError, Result: trackers.Unknown(), Err: err.Error()}
	}

	v, err := bencode.Decode(body)
	if err != nil {
		return trackers.Response{Status: trackers.StatusError, Result: trackers.Unknown(), Err: "bdecode: " + err.Error()}
	}
	top, ok := bencode.AsDict(v)
	if !ok {
		return trackers.Response{Status: trackers.StatusError, Result: trackers.Unknown(), Err: "not a dict"}
	}
	if fr, ok := bencode.DictString(top, "failure reason"); ok && fr != "" {
		low := strings.ToLower(fr)
		if strings.Contains(low, "not registered") || strings.Contains(low, "unregistered") || strings.Contains(low, "unknown") {
			return trackers.Response{Status: trackers.StatusNotFound, Result: trackers.Unknown()}
		}
		return trackers.Response{Status: trackers.StatusError, Result: trackers.Unknown(), Err: "tracker: " + fr}
	}

	// Peers can be either compact bytes (6 bytes per peer) or a list of dicts.
	peersRaw := top["peers"]
	var peerCount int32
	switch p := peersRaw.(type) {
	case []byte:
		peerCount = int32(len(p) / 6)
	case []any:
		peerCount = int32(len(p))
	}

	// Subtract 1 for "self-echo" — Rutracker always includes our own peer in the list.
	if peerCount > 0 {
		peerCount--
	}

	// Some trackers include complete/incomplete even in announce responses.
	seeds, hasSeed := bencode.DictInt(top, "complete")
	leech, hasLeech := bencode.DictInt(top, "incomplete")

	res := trackers.ScrapeResult{
		Seeders:   -1,
		Leechers:  -1,
		Completed: -1,
		PeerCount: peerCount,
	}
	if hasSeed {
		res.Seeders = clip32(seeds)
	}
	if hasLeech {
		res.Leechers = clip32(leech)
	}

	// Status: if we got any peer AND tracker didn't error, it's OK.
	// If peer_count is 0 (= 1 self-echo only) AND no stats, treat as not found
	// to avoid false positives from rutracker's always-includes-self behavior.
	if peerCount == 0 && !hasSeed && !hasLeech {
		return trackers.Response{Status: trackers.StatusNotFound, Result: trackers.Unknown()}
	}
	return trackers.Response{Status: trackers.StatusOK, Result: res}
}

func clip32(n int64) int32 {
	const max = int32(^uint32(0) >> 1)
	if n < 0 {
		return 0
	}
	if n > int64(max) {
		return max
	}
	return int32(n)
}

func intStr(n int) string {
	// Small helper so we don't drag strconv just for this.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
