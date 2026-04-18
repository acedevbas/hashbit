// Package rutor implements HTTP scrape for Rutor's trackers.
// Endpoint: bt2/bt3.new-team.info:2710/scrape
// Protocol: BEP 48 (multi info_hash scrape)
// Data: seeders, leechers, completed
package rutor

import (
	"context"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/acedevbas/hashbit/internal/bencode"
	"github.com/acedevbas/hashbit/internal/httpclient"
	"github.com/acedevbas/hashbit/internal/trackers"
)

var Mirrors = []string{
	"http://bt2.new-team.info:2710/scrape",
	"http://bt3.new-team.info:2710/scrape",
}

type Scraper struct {
	http *httpclient.Client
}

func New(hc *httpclient.Client) *Scraper { return &Scraper{http: hc} }

// Scrape performs a batch scrape for hashes against all mirrors in parallel.
// Results across mirrors are merged via max() — the best-informed mirror wins per hash.
func (s *Scraper) Scrape(ctx context.Context, hashes []string) map[string]trackers.Response {
	result := make(map[string]trackers.Response, len(hashes))
	for _, h := range hashes {
		result[h] = trackers.Response{Status: trackers.StatusNotFound, Result: trackers.Unknown()}
	}
	if len(hashes) == 0 {
		return result
	}

	// Query mirrors sequentially — usually one works, fallbacks are rare.
	for _, base := range Mirrors {
		found := scrapeOne(ctx, s.http, base, hashes)
		// Merge
		for h, r := range found {
			cur := result[h]
			if r.Result.Seeders > cur.Result.Seeders {
				cur.Result.Seeders = r.Result.Seeders
			}
			if r.Result.Leechers > cur.Result.Leechers {
				cur.Result.Leechers = r.Result.Leechers
			}
			if r.Result.Completed > cur.Result.Completed {
				cur.Result.Completed = r.Result.Completed
			}
			if r.Status == trackers.StatusOK {
				cur.Status = trackers.StatusOK
			}
			result[h] = cur
		}
	}
	return result
}

func scrapeOne(ctx context.Context, hc *httpclient.Client, base string, hashes []string) map[string]trackers.Response {
	out := make(map[string]trackers.Response, len(hashes))

	var sb strings.Builder
	sb.WriteString(base)
	sb.WriteByte('?')
	for i, h := range hashes {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 20 {
			continue
		}
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString("info_hash=")
		sb.WriteString(url.QueryEscape(string(raw)))
	}
	fullURL := sb.String()

	body, _, err := hc.Get(ctx, fullURL)
	if err != nil {
		for _, h := range hashes {
			out[h] = trackers.Response{Status: trackers.StatusError, Result: trackers.Unknown(), Err: err.Error()}
		}
		return out
	}

	v, err := bencode.Decode(body)
	if err != nil {
		for _, h := range hashes {
			out[h] = trackers.Response{Status: trackers.StatusError, Result: trackers.Unknown(), Err: "bdecode: " + err.Error()}
		}
		return out
	}
	top, ok := bencode.AsDict(v)
	if !ok {
		return out
	}
	files, ok := bencode.AsDict(top["files"])
	if !ok {
		return out
	}

	for _, h := range hashes {
		raw, err := hex.DecodeString(h)
		if err != nil {
			continue
		}
		entry, ok := bencode.AsDict(files[string(raw)])
		if !ok {
			continue // this hash not in response (rutor doesn't know it)
		}
		seeds, _ := bencode.DictInt(entry, "complete")
		leech, _ := bencode.DictInt(entry, "incomplete")
		comp, _ := bencode.DictInt(entry, "downloaded")
		out[h] = trackers.Response{
			Status: trackers.StatusOK,
			Result: trackers.ScrapeResult{
				Seeders:   clipInt32(seeds),
				Leechers:  clipInt32(leech),
				Completed: clipInt32(comp),
				PeerCount: -1,
			},
		}
	}
	return out
}

func clipInt32(n int64) int32 {
	const max = int32(^uint32(0) >> 1)
	if n < 0 {
		return 0
	}
	if n > int64(max) {
		return max
	}
	return int32(n)
}
