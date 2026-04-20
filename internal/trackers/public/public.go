package public

import (
	"context"
	"sync"
	"time"

	"github.com/acedevbas/hashbit/internal/httpclient"
	"github.com/acedevbas/hashbit/internal/trackers"
)

// Scraper queries a curated list of public trackers (HTTP and UDP) for each
// info_hash and returns the max-aggregated result across them. One "public"
// response already represents the best signal obtainable without auth.
//
// Up to four layers run in parallel per Scrape call:
//  1. HTTP BEP 48 multi-hash scrape (cheap, counts-only, many hashes per req)
//  2. UDP BEP 15 multi-hash scrape (cheap, counts-only, ~70 hashes per req)
//  3. UDP BEP 15 action=1 announce (expensive, one req per (hash, tracker),
//     but returns authoritative swarm counts AND up to ~200 peers per reply)
//  4. HTTP BEP 3 /announce (expensive, one req per (hash, tracker), returns
//     counts AND a compact peer list; complements layer 3 on HTTP-only trackers)
//
// Layers (1) and (2) converge in a few seconds for a whole batch; layers (3)
// and (4) take len(hashes)*len(endpoints) round-trips. Announce is disabled by
// default on large ticks; turn on via EnableAnnounce when per-hash peer
// discovery matters more than tick latency.
//
// Endpoint lists can be refreshed in the background from ngosang/trackerslist
// — see refresh.go. Reads go through httpEndpoints() / udpEndpoints() under a
// RWMutex so the refresher never interrupts an in-flight Scrape.
type Scraper struct {
	http           *httpclient.Client
	concurrency    int
	enableAnnounce bool

	// Endpoint lists, guarded by endpointsMu so the refresher can hot-swap
	// them without tearing a concurrent Scrape's view of the world. A Scrape
	// takes a snapshot at entry and uses that for the whole fan-out.
	endpointsMu sync.RWMutex
	httpURLs    []string
	udpURLs     []string

	// Refresh configuration. If refreshInterval <= 0 the refresher is never
	// started and the lists stay at whatever was seeded at construction.
	refreshInterval time.Duration
	refreshHTTPURL  string
	refreshUDPURL   string
	stopRefresh     chan struct{}
	closeOnce       sync.Once
}

// New builds a scraper with the default endpoint lists. concurrency caps how
// many endpoint flows run at once; 32 is a good balance on a small VPS.
// announceEnabled adds UDP+HTTP announce alongside scrape — expensive but
// returns peer lists of up to ~200 peers per tracker per hash.
//
// If refreshInterval > 0, a background goroutine will periodically pull
// current endpoint lists from ngosang/trackerslist (or the provided override
// URLs) and swap them in-place. Set to 0 to disable refresh and stick with
// the bundled defaults. Call Close() to stop the refresher.
func New(hc *httpclient.Client, concurrency int, announceEnabled bool,
	refreshInterval time.Duration, refreshHTTPURL, refreshUDPURL string) *Scraper {
	if concurrency <= 0 {
		concurrency = 32
	}
	s := &Scraper{
		http:            hc,
		httpURLs:        HTTPEndpoints,
		udpURLs:         UDPEndpoints,
		concurrency:     concurrency,
		enableAnnounce:  announceEnabled,
		refreshInterval: refreshInterval,
		refreshHTTPURL:  refreshHTTPURL,
		refreshUDPURL:   refreshUDPURL,
		stopRefresh:     make(chan struct{}),
	}
	if refreshInterval > 0 {
		go s.refreshLoop()
	}
	return s
}

// HTTPEndpoints returns a snapshot of the currently-active HTTP scrape URLs.
// The returned slice is a copy — callers can iterate it freely without
// coordinating with the refresher.
func (s *Scraper) HTTPEndpoints() []string {
	s.endpointsMu.RLock()
	defer s.endpointsMu.RUnlock()
	out := make([]string, len(s.httpURLs))
	copy(out, s.httpURLs)
	return out
}

// UDPEndpoints returns a snapshot of the currently-active UDP endpoint URLs.
func (s *Scraper) UDPEndpoints() []string {
	s.endpointsMu.RLock()
	defer s.endpointsMu.RUnlock()
	out := make([]string, len(s.udpURLs))
	copy(out, s.udpURLs)
	return out
}

// SetEndpoints atomically replaces both endpoint lists. Nil / empty inputs
// are ignored so callers can update just one list without clearing the other.
// Intended for the refresh goroutine and tests.
func (s *Scraper) SetEndpoints(httpURLs, udpURLs []string) {
	s.endpointsMu.Lock()
	defer s.endpointsMu.Unlock()
	if len(httpURLs) > 0 {
		s.httpURLs = httpURLs
	}
	if len(udpURLs) > 0 {
		s.udpURLs = udpURLs
	}
}

// Close stops the background refresher. Safe to call multiple times.
// Does NOT close the http client — that's owned by the caller.
func (s *Scraper) Close() error {
	s.closeOnce.Do(func() { close(s.stopRefresh) })
	return nil
}

// Scrape fans out all hashes to every configured HTTP+UDP endpoint in parallel,
// merges per-hash fields via max(), and returns the aggregate map.
// Unknown hashes (no endpoint had data) remain as StatusNotFound.
func (s *Scraper) Scrape(ctx context.Context, hashes []string) map[string]trackers.Response {
	result := make(map[string]trackers.Response, len(hashes))
	for _, h := range hashes {
		result[h] = trackers.Response{Status: trackers.StatusNotFound, Result: trackers.Unknown()}
	}
	if len(hashes) == 0 {
		return result
	}

	// Snapshot the endpoint lists once per call. If the refresher runs mid-
	// scrape we still complete with the view we started with, avoiding partial
	// coverage anomalies across the four layers.
	httpURLs := s.HTTPEndpoints()
	udpURLs := s.UDPEndpoints()

	sem := make(chan struct{}, s.concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	layers := 2
	if s.enableAnnounce {
		layers = 4
	}
	wg.Add(layers)

	go func() {
		defer wg.Done()
		scrapeHTTP(ctx, s.http, httpURLs, hashes, result, &mu, sem)
	}()
	go func() {
		defer wg.Done()
		scrapeUDP(ctx, udpURLs, hashes, result, &mu, sem)
	}()
	if s.enableAnnounce {
		go func() {
			defer wg.Done()
			announceUDP(ctx, udpURLs, hashes, result, &mu, sem)
		}()
		go func() {
			defer wg.Done()
			announceHTTP(ctx, s.http, httpURLs, hashes, result, &mu, sem)
		}()
	}
	wg.Wait()

	return result
}
