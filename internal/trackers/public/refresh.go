// Periodic tracker-list refresh from ngosang/trackerslist.
//
// The curated community list at github.com/ngosang/trackerslist is updated
// hourly with live/working public trackers. Pulling it in-process once every
// few hours keeps our hit rate high without a rebuild — stale hardcoded
// endpoints are the #1 cause of public-tracker data rot.
//
// Failure is always non-fatal: if the refresh fetch errors or returns garbage,
// we keep the previous list (which on first boot is the bundled default in
// endpoints.go). A partial success (one list OK, the other failed) is allowed.
package public

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"time"
)

// Default upstream URLs. Override via PUBLIC_REFRESH_URL_{HTTP,UDP} to pin a
// fork or a mirror. The .txt files are one URL per line.
const (
	DefaultRefreshURLHTTP = "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_http.txt"
	DefaultRefreshURLUDP  = "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_udp.txt"

	// refreshFetchTimeout bounds a single HTTP GET of a list file. The files
	// are <32 KiB so this is generous; keeps us from hanging on a slow CDN.
	refreshFetchTimeout = 30 * time.Second
)

// refreshLoop is the background goroutine that periodically pulls fresh
// endpoint lists and swaps them into the Scraper. It exits on ctx.Done() or
// when the caller signals s.stopRefresh.
func (s *Scraper) refreshLoop() {
	// Fire once on startup so new deployments don't have to wait a full
	// interval for the first refresh. Failure is silently tolerated.
	s.refreshOnce()

	t := time.NewTicker(s.refreshInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stopRefresh:
			return
		case <-t.C:
			s.refreshOnce()
		}
	}
}

// refreshOnce fetches both lists concurrently and atomically swaps the ones
// that parsed successfully. Keeping them independent means an outage at
// raw.githubusercontent.com for just the HTTP file still updates the UDP list.
func (s *Scraper) refreshOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), refreshFetchTimeout)
	defer cancel()

	httpURLs := fetchAndParse(ctx, s.refreshHTTPURL, normalizeHTTPEndpoint)
	udpURLs := fetchAndParse(ctx, s.refreshUDPURL, normalizeUDPEndpoint)

	s.endpointsMu.Lock()
	defer s.endpointsMu.Unlock()
	if len(httpURLs) > 0 {
		s.httpURLs = httpURLs
	}
	if len(udpURLs) > 0 {
		s.udpURLs = udpURLs
	}
}

// fetchAndParse downloads one list file and returns the filtered, normalized
// endpoint list. Returns nil on any error so the caller retains the fallback.
func fetchAndParse(ctx context.Context, url string, normalize func(string) string) []string {
	if url == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	// Stand-alone client — we deliberately don't reuse the tracker httpclient
	// (different User-Agent story, different timeout semantics).
	client := &http.Client{Timeout: refreshFetchTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var out []string
	scan := bufio.NewScanner(resp.Body)
	scan.Buffer(make([]byte, 0, 4096), 1024*1024) // raise token cap for safety
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if url := normalize(line); url != "" {
			out = append(out, url)
		}
	}
	if scan.Err() != nil {
		return nil
	}
	return out
}

// normalizeHTTPEndpoint converts an announce URL from ngosang into the scrape
// form our HTTP code expects. The upstream file stores announce URLs like
// "http://tracker/announce"; we swap the LAST "/announce" with "/scrape".
// Anything that doesn't speak http:// or https:// is dropped defensively.
func normalizeHTTPEndpoint(line string) string {
	if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
		return ""
	}
	idx := strings.LastIndex(line, "/announce")
	if idx < 0 {
		// Already a scrape URL, or malformed; accept as-is if it looks like
		// a scrape endpoint, else skip rather than guess.
		if strings.Contains(line, "/scrape") {
			return line
		}
		return ""
	}
	return line[:idx] + "/scrape" + line[idx+len("/announce"):]
}

// normalizeUDPEndpoint strips the trailing "/announce" from a UDP URL so it
// matches the host:port form our udp_scrape/udp_announce code expects. The
// UDP tracker protocol ignores the path portion entirely (BEP 15), but our
// parser in scrapeUDPOne does an IndexByte('/') anyway, so leaving /announce
// would work — we strip it for cleaner logs and consistency with endpoints.go.
func normalizeUDPEndpoint(line string) string {
	if !strings.HasPrefix(line, "udp://") {
		return ""
	}
	if idx := strings.LastIndex(line, "/announce"); idx >= 0 {
		return line[:idx] + line[idx+len("/announce"):]
	}
	return line
}
