// PassivePeerCache is the write-behind cache between the KRPC handlers and
// PostgreSQL. Design goals:
//
//  1. KRPC-handler latency stays sub-millisecond: Record() is a non-blocking
//     channel send, never a DB round-trip.
//  2. Under pathological load, we drop new announces rather than grow memory
//     without bound or back up the UDP read loop.
//  3. Per-hash storage is capped (config.DHTPassiveMaxPerHash) so a single
//     viral torrent cannot flood the table. The in-memory ring tracks the
//     approximate count per hash without reading back from the DB on every
//     announce.
//  4. Reads (FreshPeers) go to the DB directly — the in-memory cache is
//     a write staging buffer, not a query layer. Callers who want low-latency
//     reads should memoize at the query call site.
package dht

import (
	"context"
	"sync"
	"time"

	"github.com/acedevbas/hashbit/internal/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PassivePeerCache batches observed announce_peer records and flushes them
// to Postgres on a timer or when the buffer saturates.
type PassivePeerCache struct {
	pool   *pgxpool.Pool
	ch     chan passiveObs
	flush  time.Duration
	maxPer int

	// counts is a best-effort per-hash counter used to skip writes once a hash
	// is saturated. It is NOT the source of truth — the DB is — but it
	// prevents millions of no-op UPSERTs for a single viral hash. It drifts
	// downward when we restart (counter is in-memory only), which is fine:
	// we'll quickly re-accumulate up to the cap.
	mu     sync.Mutex
	counts map[string]int

	closeOnce sync.Once
	done      chan struct{}
}

type passiveObs struct {
	infohash string
	peer     string
}

// NewPassivePeerCache constructs the cache. Call Start to launch the flusher
// goroutine. The channel buffer is sized at 10k — at typical incoming rates
// (hundreds of announces/min for a popular node) this is many minutes of head-
// room, and at pathological rates we shed load by dropping new observations
// rather than blocking the UDP reader.
func NewPassivePeerCache(pool *pgxpool.Pool, maxPerHash int) *PassivePeerCache {
	if maxPerHash <= 0 {
		maxPerHash = 500
	}
	return &PassivePeerCache{
		pool:   pool,
		ch:     make(chan passiveObs, 10_000),
		flush:  2 * time.Second,
		maxPer: maxPerHash,
		counts: make(map[string]int, 4096),
		done:   make(chan struct{}),
	}
}

// Record is the public write-path (implements PeerRecorder). Never blocks:
// a full channel drops the observation. The caller is the UDP read loop and
// we do not want to stall it; losing one announce out of many for the same
// hash is acceptable because popular hashes receive announces continuously.
func (c *PassivePeerCache) Record(infohash, peer string) {
	c.mu.Lock()
	cnt := c.counts[infohash]
	if cnt >= c.maxPer {
		c.mu.Unlock()
		return
	}
	c.counts[infohash] = cnt + 1
	c.mu.Unlock()

	select {
	case c.ch <- passiveObs{infohash, peer}:
	default:
		// Buffer full — shed load. Roll back the count so we don't permanently
		// over-report saturation after a short spike.
		c.mu.Lock()
		c.counts[infohash]--
		c.mu.Unlock()
	}
}

// Start launches the flusher. Stops on ctx cancel or Close.
func (c *PassivePeerCache) Start(ctx context.Context) {
	go c.runFlusher(ctx)
}

// Close signals the flusher to drain and exit. Idempotent.
func (c *PassivePeerCache) Close() {
	c.closeOnce.Do(func() { close(c.done) })
}

func (c *PassivePeerCache) runFlusher(ctx context.Context) {
	ticker := time.NewTicker(c.flush)
	defer ticker.Stop()
	pending := make([]passiveObs, 0, 512)
	doFlush := func() {
		if len(pending) == 0 {
			return
		}
		// Short write deadline: if the DB is slow we'd rather drop this
		// batch than back up memory indefinitely. Observations are
		// best-effort; a missed write is re-observable.
		flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		for _, p := range pending {
			_ = db.RecordPassivePeer(flushCtx, c.pool, p.infohash, p.peer)
		}
		cancel()
		pending = pending[:0]
	}
	for {
		select {
		case <-ctx.Done():
			doFlush()
			return
		case <-c.done:
			doFlush()
			return
		case <-ticker.C:
			doFlush()
		case obs := <-c.ch:
			pending = append(pending, obs)
			// Flush early if we've collected a meaningful batch to amortise
			// per-row DB overhead; 500 rows is comfortably below pgx batch
			// default transport limits.
			if len(pending) >= 500 {
				doFlush()
			}
		}
	}
}

// FreshPeers asks the DB for peers seen within `within` for `infohash`. Used
// by the active DHT scraper to skip redundant lookups when a warm cache
// already has recent observations.
func (c *PassivePeerCache) FreshPeers(ctx context.Context, infohash string, within time.Duration, limit int) ([]string, error) {
	return db.FreshPassivePeers(ctx, c.pool, infohash, within, limit)
}

// RunJanitor periodically deletes rows older than cutoffAge. Intended to run
// as its own long-lived goroutine (one per process). Returns when ctx is done.
func (c *PassivePeerCache) RunJanitor(ctx context.Context, cutoffAge, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-cutoffAge)
			_, _ = db.PassivePeersExpireOlderThan(ctx, c.pool, cutoff)
			c.resetCountsApprox()
		}
	}
}

// resetCountsApprox clears the per-hash counter periodically so old spikes
// don't permanently pin a hash at "saturated". The DB remains the truth for
// the cap; this drift is acceptable because the next 500 announces will
// simply ON CONFLICT DO UPDATE on existing rows or insert new ones, and
// `RecordPassivePeer` is idempotent.
func (c *PassivePeerCache) resetCountsApprox() {
	c.mu.Lock()
	// Rebuild empty: safer than halving, still fast.
	c.counts = make(map[string]int, 4096)
	c.mu.Unlock()
}
