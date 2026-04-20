package public

import (
	"context"
	"encoding/hex"
	"net/url"
	"strings"
	"sync"

	"github.com/acedevbas/hashbit/internal/bencode"
	"github.com/acedevbas/hashbit/internal/httpclient"
	"github.com/acedevbas/hashbit/internal/trackers"
)

// scrapeHTTP queries each configured HTTP endpoint in parallel (capped by sem)
// and merges per-hash results into `results` via max(). Safe for concurrent use.
func scrapeHTTP(ctx context.Context, hc *httpclient.Client, endpoints []string, hashes []string,
	results map[string]trackers.Response, mu *sync.Mutex, sem chan struct{}) {

	if len(endpoints) == 0 || len(hashes) == 0 {
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
			partial := scrapeHTTPOne(ctx, hc, endpoint, hashes)
			mu.Lock()
			mergeInto(results, partial)
			mu.Unlock()
		}(ep)
	}
	wg.Wait()
}

// scrapeHTTPOne sends a single BEP48 multi-hash scrape request to one endpoint.
// Returns a partial map: only hashes present in the tracker's response.
func scrapeHTTPOne(ctx context.Context, hc *httpclient.Client, base string, hashes []string) map[string]trackers.Response {
	out := make(map[string]trackers.Response, len(hashes))

	var sb strings.Builder
	sb.WriteString(base)
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	sb.WriteString(sep)
	first := true
	for _, h := range hashes {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 20 {
			continue
		}
		if !first {
			sb.WriteByte('&')
		}
		first = false
		sb.WriteString("info_hash=")
		sb.WriteString(url.QueryEscape(string(raw)))
	}
	if first {
		return out // no valid hashes
	}

	body, _, err := hc.Get(ctx, sb.String())
	if err != nil {
		return out // silent — one dead endpoint doesn't poison the batch
	}
	v, err := bencode.Decode(body)
	if err != nil {
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
			continue
		}
		seeds, _ := bencode.DictInt(entry, "complete")
		leech, _ := bencode.DictInt(entry, "incomplete")
		comp, _ := bencode.DictInt(entry, "downloaded")
		if seeds == 0 && leech == 0 && comp == 0 {
			continue // tracker knows hash but reports zero stats — skip to avoid wiping a better mirror's data
		}
		out[h] = trackers.Response{
			Status: trackers.StatusOK,
			Result: trackers.ScrapeResult{
				Seeders:   clip32(seeds),
				Leechers:  clip32(leech),
				Completed: clip32(comp),
				PeerCount: -1,
			},
		}
	}
	return out
}

// mergeInto merges src into dst via max() per field. StatusOK beats NotFound beats Error.
// Caller must hold the mutex guarding dst.
func mergeInto(dst, src map[string]trackers.Response) {
	for h, r := range src {
		cur, had := dst[h]
		if !had {
			cur = trackers.Response{Status: trackers.StatusNotFound, Result: trackers.Unknown()}
		}
		if r.Result.Seeders > cur.Result.Seeders {
			cur.Result.Seeders = r.Result.Seeders
		}
		if r.Result.Leechers > cur.Result.Leechers {
			cur.Result.Leechers = r.Result.Leechers
		}
		if r.Result.Completed > cur.Result.Completed {
			cur.Result.Completed = r.Result.Completed
		}
		if r.Result.PeerCount > cur.Result.PeerCount {
			cur.Result.PeerCount = r.Result.PeerCount
		}
		if r.Status == trackers.StatusOK {
			cur.Status = trackers.StatusOK
		}
		dst[h] = cur
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
