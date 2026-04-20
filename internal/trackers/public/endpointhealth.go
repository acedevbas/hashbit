package public

import "sync"

// endpointHealth is a per-Scrape circuit breaker that short-circuits fan-out
// to trackers that proved unresponsive on their first contact. Without it a
// dead tracker × N hashes burns the full (hash-count × per-request-timeout)
// budget for zero yield, and with multiple dead trackers in the list this
// dominates tick time.
//
// Semantics: a tracker is "bad" for the rest of this Scrape as soon as one
// goroutine reports it unreachable (connect timeout / DNS fail / tracker
// error). Subsequent goroutines check Bad(endpoint) first and bail before
// opening a socket. The map is scoped to a single Scrape call — the next
// tick starts fresh, so a tracker that recovered gets another chance
// promptly.
type endpointHealth struct {
	mu  sync.RWMutex
	bad map[string]struct{}
}

func newEndpointHealth() *endpointHealth {
	return &endpointHealth{bad: make(map[string]struct{}, 8)}
}

// Bad reports whether endpoint has been previously marked dead in this Scrape.
// Safe for concurrent reads.
func (h *endpointHealth) Bad(endpoint string) bool {
	h.mu.RLock()
	_, ok := h.bad[endpoint]
	h.mu.RUnlock()
	return ok
}

// Mark records endpoint as dead. Idempotent; repeated calls are cheap.
func (h *endpointHealth) Mark(endpoint string) {
	h.mu.Lock()
	h.bad[endpoint] = struct{}{}
	h.mu.Unlock()
}
