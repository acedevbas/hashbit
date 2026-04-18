// Package kinozal implements announce-stopped polling for Kinozal.
// Kinozal does not support /scrape, so we send an announce with event=stopped
// and numwant=0, which returns seeder/leecher counts without adding us to the swarm.
//
// Requires a personal passkey (uk= parameter) from a logged-in download.
package kinozal

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

// Mirror endpoints. uk= passkey is appended at call time.
var Mirrors = []string{
	"http://tr1.torrent4me.com/ann",
	"http://tr1.tor4me.info/ann",
}

type Scraper struct {
	http *httpclient.Client
	uk   string // personal user passkey
}

func New(hc *httpclient.Client, passkey string) *Scraper {
	return &Scraper{http: hc, uk: passkey}
}

// Scrape queries a single hash via announce-stopped on all mirrors.
// Mirrors are tried sequentially; first successful response wins.
// Returns a map keyed by the hash for consistency with batch scrapers.
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

	var lastErr string
	for _, base := range Mirrors {
		resp := s.announceStopped(ctx, base, raw)
		if resp.Status == trackers.StatusOK {
			return resp
		}
		if resp.Status == trackers.StatusNotFound {
			// Authoritative "unknown" — no point asking other mirrors.
			return resp
		}
		lastErr = resp.Err
	}
	return trackers.Response{Status: trackers.StatusError, Result: trackers.Unknown(), Err: lastErr}
}

func (s *Scraper) announceStopped(ctx context.Context, base string, raw []byte) trackers.Response {
	peerID := make([]byte, 20)
	copy(peerID, "-UT3550-")
	_, _ = rand.Read(peerID[8:])

	q := url.Values{}
	// Order matters for some trackers — but url.Values sorts alphabetically.
	// Since we don't see issues in tests, we accept this.
	q.Set("info_hash", string(raw))
	q.Set("peer_id", string(peerID))
	q.Set("port", "6881")
	q.Set("uploaded", "0")
	q.Set("downloaded", "0")
	q.Set("left", "0")
	q.Set("event", "stopped")
	q.Set("numwant", "0")
	q.Set("compact", "1")
	q.Set("no_peer_id", "1")
	if s.uk != "" {
		q.Set("uk", s.uk)
	}

	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	fullURL := base + sep + q.Encode()

	body, _, err := s.http.Get(ctx, fullURL)
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
		// "unregistered torrent" / "torrent not registered" / similar → hash unknown
		low := strings.ToLower(fr)
		if strings.Contains(low, "unregistered") || strings.Contains(low, "not registered") || strings.Contains(low, "unknown") {
			return trackers.Response{Status: trackers.StatusNotFound, Result: trackers.Unknown()}
		}
		return trackers.Response{Status: trackers.StatusError, Result: trackers.Unknown(), Err: "tracker: " + fr}
	}
	seedsV, hasSeed := top["complete"]
	leechV, hasLeech := top["incomplete"]
	if !hasSeed {
		return trackers.Response{Status: trackers.StatusNotFound, Result: trackers.Unknown()}
	}
	seeds, _ := bencode.AsInt(seedsV)
	var leech int64
	if hasLeech {
		leech, _ = bencode.AsInt(leechV)
	}
	return trackers.Response{
		Status: trackers.StatusOK,
		Result: trackers.ScrapeResult{
			Seeders:   clip32(seeds),
			Leechers:  clip32(leech),
			Completed: -1,
			PeerCount: -1,
		},
	}
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
