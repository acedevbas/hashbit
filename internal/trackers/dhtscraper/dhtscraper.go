// Package dhtscraper is a Scraper that uses the Mainline DHT as its data
// source. Per hash it runs an iterative get_peers lookup (BEP 5) and, when
// supported, collects BEP 33 bloom filters from every responding node.
//
// The scraper holds a POOL of N independent dht.Clients, each with its own
// random node id and UDP socket. Different node ids anchor different paths
// through Kademlia space, so each client converges on a partially-different
// set of "closest to target" peers. Fanning the same hash to all N clients
// in parallel and unioning results roughly multiplies peer coverage and
// BEP 33 responder count by ~2-3× vs a single client.
//
// Why this works well where TCP handshake fingerprints do not:
//   - no NAT traversal needed (pure UDP DHT traffic);
//   - no rate-limits from individual trackers;
//   - BEP 33 nodes already host aggregate swarm stats, so a single lookup can
//     give a population estimate for tens/hundreds of peers without touching
//     any of them.
//
// Trade-offs:
//   - private torrents (rutracker, kinozal) are not announced to DHT by
//     well-behaved clients, so this scraper returns not_found for them.
//   - BEP 33 estimates are time-aggregated: 10-20 % of DHT nodes implement
//     the extension, each remembers everyone who announced in the last
//     ~30 min, so the number can exceed a classical tracker's instant count.
package dhtscraper

import (
	"context"
	"encoding/hex"
	"sync"
	"time"

	"github.com/acedevbas/hashbit/internal/dht"
	"github.com/acedevbas/hashbit/internal/trackers"
)

// PassiveCache is the read interface into the passive DHT's harvested
// (infohash -> recent peers) store. Defined as an interface so tests (and
// alternative backends) can substitute a simple in-memory map without
// pulling the production Postgres-backed implementation. nil is a valid
// zero — when no cache is wired the scraper behaves exactly as before.
type PassiveCache interface {
	FreshPeers(ctx context.Context, infohash string, within time.Duration, limit int) ([]string, error)
}

// Scraper implements scheduler.Scraper using a pool of DHT clients.
type Scraper struct {
	clients     []*dht.Client
	concurrency int
	opts        dht.Options

	// passiveCache, if non-nil, is consulted BEFORE the active lookups. The
	// cache supplements rather than replaces live queries: a passive hit
	// confirms peer existence cheaply, but an active lookup may still
	// discover BEP 33 responders and fresh peers the cache missed.
	passiveCache   PassiveCache
	passivePeerTTL time.Duration
	passivePeerCap int
}

// SetPassiveCache wires a passive-peer cache for cheap pre-check lookups.
// ttl is the "still fresh" window; limit caps the number of peers read per
// hash. Passing nil detaches the cache (restores the original behaviour).
func (s *Scraper) SetPassiveCache(c PassiveCache, ttl time.Duration, limit int) {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if limit <= 0 {
		limit = 200
	}
	s.passiveCache = c
	s.passivePeerTTL = ttl
	s.passivePeerCap = limit
}

// New constructs a Scraper with `numClients` long-lived DHT clients. Each
// client owns its own UDP socket and random node id; different ids anchor
// different Kademlia routing paths, so spreading queries across the pool
// materially broadens swarm coverage.
//
// concurrency caps simultaneous per-hash operations across the whole pool
// (one hash fans out to numClients lookups, each taking one slot). A slot
// pool of 64 with numClients=4 lets 16 hashes execute in parallel.
//
// lookupTimeout bounds one hash on one client. alpha is Kademlia α.
func New(numClients, concurrency int, lookupTimeout time.Duration, alpha int) (*Scraper, error) {
	if numClients <= 0 {
		numClients = 1
	}
	if concurrency <= 0 {
		concurrency = 32
	}
	if lookupTimeout <= 0 {
		lookupTimeout = 12 * time.Second
	}
	if alpha <= 0 {
		alpha = dht.Alpha
	}
	clients := make([]*dht.Client, 0, numClients)
	for i := 0; i < numClients; i++ {
		c, err := dht.NewClient()
		if err != nil {
			for _, existing := range clients {
				_ = existing.Close()
			}
			return nil, err
		}
		clients = append(clients, c)
	}
	return &Scraper{
		clients:     clients,
		concurrency: concurrency,
		opts:        dht.Options{Timeout: lookupTimeout, Alpha: alpha},
	}, nil
}

// Close releases every underlying DHT socket. Safe to call once at shutdown.
func (s *Scraper) Close() error {
	for _, c := range s.clients {
		_ = c.Close()
	}
	return nil
}

// Scrape runs parallel DHT lookups for each hash across all pool clients and
// maps the result to the internal trackers.Response shape used by the
// scheduler and aggregation.
//
// Response semantics (per hash):
//   - ≥1 BEP 33 responder across any client → StatusOK with
//     Seeders/Leechers = estimate from OR-merged bloom filters.
//   - only raw peers → StatusOK with PeerCount = union size (like rutracker).
//   - nothing → StatusNotFound.
func (s *Scraper) Scrape(ctx context.Context, hashes []string) map[string]trackers.Response {
	result := make(map[string]trackers.Response, len(hashes))
	for _, h := range hashes {
		result[h] = trackers.Response{Status: trackers.StatusNotFound, Result: trackers.Unknown()}
	}
	if len(hashes) == 0 {
		return result
	}

	sem := make(chan struct{}, s.concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, h := range hashes {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			resp := s.scrapeOne(ctx, h, sem)
			mu.Lock()
			result[h] = resp
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	return result
}

// scrapeOne fans out one hash to every client in the pool, concurrently,
// respecting the shared concurrency semaphore; merges returned peers and
// bloom filters; produces a single trackers.Response.
func (s *Scraper) scrapeOne(ctx context.Context, hexHash string, sem chan struct{}) trackers.Response {
	raw, err := hex.DecodeString(hexHash)
	if err != nil || len(raw) != 20 {
		return trackers.Response{Status: trackers.StatusError, Result: trackers.Unknown(), Err: "bad hash"}
	}
	var ih [20]byte
	copy(ih[:], raw)

	type outcome struct {
		peers           []string
		bep33Responders int
		bfSeeds         [256]byte
		bfPeers         [256]byte
		err             error
	}
	outCh := make(chan outcome, len(s.clients))

	// Pre-consult the passive cache. Any hit still complements (not replaces)
	// the active lookup: BEP 33 estimates require live responders, and stale
	// cache entries exclude peers that just joined the swarm. A short DB read
	// timeout prevents a slow cache from slowing every lookup.
	var cachedPeers []string
	if s.passiveCache != nil {
		cacheCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		if fresh, err := s.passiveCache.FreshPeers(cacheCtx, hexHash, s.passivePeerTTL, s.passivePeerCap); err == nil {
			cachedPeers = fresh
		}
		cancel()
	}

	for _, c := range s.clients {
		go func(c *dht.Client) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				outCh <- outcome{err: ctx.Err()}
				return
			}
			r, err := c.Lookup(ctx, ih, s.opts)
			if err != nil {
				outCh <- outcome{err: err}
				return
			}
			outCh <- outcome{
				peers:           r.Peers,
				bep33Responders: r.BEP33Responders,
				bfSeeds:         r.MergedBFSeeds,
				bfPeers:         r.MergedBFPeers,
			}
		}(c)
	}

	peersSet := make(map[string]struct{})
	var fusedSeeds, fusedPeers [256]byte
	totalBEP33 := 0
	gotAnyResult := false

	// Seed with cached peers first so they survive even if every active
	// lookup fails — the cache alone is enough to report StatusOK.
	for _, p := range cachedPeers {
		peersSet[p] = struct{}{}
	}
	if len(cachedPeers) > 0 {
		gotAnyResult = true
	}

	for i := 0; i < len(s.clients); i++ {
		o := <-outCh
		if o.err != nil {
			continue
		}
		gotAnyResult = true
		for _, p := range o.peers {
			peersSet[p] = struct{}{}
		}
		if o.bep33Responders > 0 {
			totalBEP33 += o.bep33Responders
			for j := 0; j < 256; j++ {
				fusedSeeds[j] |= o.bfSeeds[j]
				fusedPeers[j] |= o.bfPeers[j]
			}
		}
	}
	if !gotAnyResult {
		return trackers.Response{Status: trackers.StatusError, Result: trackers.Unknown(), Err: "all clients failed"}
	}

	// Variance rescue: on empty fan-out do an aggressive second pass with
	// wider Kademlia fanout (α*2) and a longer timeout. The first pass fails
	// when (a) batch-of-N contention saturates our UDP socket so remote
	// nodes rate-limit us mid-tick, or (b) the hash lives on seldom-visited
	// k-bucket regions that need deeper walks. Aggressive params cost one
	// extra Lookup per empty hash but rescue ~60 % of the small-swarm
	// false-negatives (production probe confirmed 8 peers on a hash our
	// batch reported as zero). Popular hashes never hit this branch.
	if len(peersSet) == 0 && totalBEP33 == 0 && len(s.clients) > 0 {
		rescueOpts := s.opts
		rescueOpts.Alpha = s.opts.Alpha * 2
		if rescueOpts.Alpha > 32 {
			rescueOpts.Alpha = 32
		}
		rescueOpts.Timeout = 30 * time.Second
		select {
		case sem <- struct{}{}:
			r, err := s.clients[0].Lookup(ctx, ih, rescueOpts)
			<-sem
			if err == nil {
				for _, p := range r.Peers {
					peersSet[p] = struct{}{}
				}
				if r.BEP33Responders > 0 {
					totalBEP33 += r.BEP33Responders
					for j := 0; j < 256; j++ {
						fusedSeeds[j] |= r.MergedBFSeeds[j]
						fusedPeers[j] |= r.MergedBFPeers[j]
					}
				}
			}
		case <-ctx.Done():
		}
	}

	resp := trackers.Response{Result: trackers.Unknown()}
	switch {
	case totalBEP33 > 0:
		resp.Status = trackers.StatusOK
		resp.Result.Seeders = clip32(dht.EstimateFromBF(fusedSeeds))
		resp.Result.Leechers = clip32(dht.EstimateFromBF(fusedPeers))
		if len(peersSet) > 0 {
			resp.Result.PeerCount = clip32(len(peersSet))
		}
	case len(peersSet) > 0:
		resp.Status = trackers.StatusOK
		resp.Result.PeerCount = clip32(len(peersSet))
	default:
		resp.Status = trackers.StatusNotFound
	}
	return resp
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
