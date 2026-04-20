package dht

// BEP 51 sample_infohashes crawler.
//
// BEP 51 lets a node advertise a random subset of the infohashes it is
// currently tracking. Issuing sample_infohashes at every DHT node we can
// reach yields a steady stream of fresh infohashes that are alive on the
// public network RIGHT NOW — a near-free discovery channel that does not
// touch any tracker.
//
// Why the first implementation failed:
//
//	Mainline DHT bootstrap nodes (router.bittorrent.com, dht.libtorrent.org,
//	...) answer find_node and get_peers but intentionally do NOT implement
//	sample_infohashes. Seeding a BFS from them therefore produces zero
//	samples: every bootstrap call returns error, the frontier never expands
//	into real BT clients, the cycle exits after ~7 visited nodes with 0
//	responses.
//
// The fix has three pieces:
//
//  1. NodePool: a shared, bounded in-memory index of DHT node endpoints
//     observed via our ordinary scrape traffic (get_peers' "nodes" field
//     from every live BT client we query for peers). Ordinary scrapes
//     populate it for free — the pool warms up to thousands of real
//     participating nodes within minutes.
//
//  2. find_node warmup: if the pool is too cold (fewer than minSeed
//     entries) we do a short iterative find_node walk from bootstraps.
//     find_node is implemented by 100% of DHT nodes, so this reliably
//     lands us in the real-client graph in 1-2 rounds and further feeds
//     the shared pool.
//
//  3. Pool-seeded BFS: the crawler samples N addresses from the pool
//     (biased toward nodes that have previously answered BEP 51) and
//     issues sample_infohashes. Successes flip the pool entry's
//     `bep51Known` flag so subsequent cycles front-load productive
//     responders, compounding the hit-rate over time.
//
// Ethics: BEP 51 responses are voluntary — a node only advertises what it
// has chosen to keep. We are not scraping anyone's private metadata; we
// are participating in Mainline DHT the way every modern BT client does.
// The `discovered_hashes` table is a log of public metadata; no content is
// ever downloaded.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/acedevbas/hashbit/internal/db"
	"github.com/acedevbas/hashbit/internal/metrics"
)

// BEP51CrawlerOptions configures the crawler. Zero-valued fields pick
// sensible defaults.
type BEP51CrawlerOptions struct {
	Interval     time.Duration // between cycles (default 10m)
	MaxNodes     int           // unique nodes sampled per cycle (default 200)
	Alpha        int           // parallel queries (default 16)
	QueryTimeout time.Duration // per KRPC call (default 2s)
	MinSeedPool  int           // pool size below which warmup runs (default 64)
	WarmupNodes  int           // nodes to collect during cold-start warmup (default 200)
}

// BEP51Crawler orchestrates periodic BEP 51 sample harvest.
type BEP51Crawler struct {
	client *Client
	pool   *NodePool
	db     *pgxpool.Pool
	log    *slog.Logger
	opts   BEP51CrawlerOptions
}

// NewBEP51Crawler returns a crawler using the supplied Client for UDP
// traffic. The pool is shared with other DHT clients — they feed node
// observations into it, the crawler drains from it. The crawler does not
// close the client on its own.
func NewBEP51Crawler(client *Client, pool *NodePool, dbPool *pgxpool.Pool, log *slog.Logger, opts BEP51CrawlerOptions) *BEP51Crawler {
	if opts.Interval <= 0 {
		opts.Interval = 10 * time.Minute
	}
	if opts.MaxNodes <= 0 {
		opts.MaxNodes = 200
	}
	if opts.Alpha <= 0 {
		opts.Alpha = 16
	}
	if opts.QueryTimeout <= 0 {
		opts.QueryTimeout = 2 * time.Second
	}
	if opts.MinSeedPool <= 0 {
		opts.MinSeedPool = 64
	}
	if opts.WarmupNodes <= 0 {
		opts.WarmupNodes = 200
	}
	return &BEP51Crawler{
		client: client,
		pool:   pool,
		db:     dbPool,
		log:    log,
		opts:   opts,
	}
}

// Run blocks until ctx is cancelled, running one crawl cycle per Interval.
func (c *BEP51Crawler) Run(ctx context.Context) {
	c.log.Info("bep51 crawler starting",
		"interval", c.opts.Interval,
		"max_nodes", c.opts.MaxNodes,
		"alpha", c.opts.Alpha,
		"min_seed_pool", c.opts.MinSeedPool,
	)
	// Initial delay before the first cycle so the dhtscraper pool has a
	// chance to feed the NodePool with observations from the first scrape
	// tick. Without this the first cycle always takes the warmup path.
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		c.runCycle(ctx)
		timer.Reset(c.opts.Interval)
	}
}

// runCycle performs one sampling pass. Hard-capped at Interval so a slow
// cycle never eats the next one.
func (c *BEP51Crawler) runCycle(ctx context.Context) {
	cycleCtx, cancel := context.WithTimeout(ctx, c.opts.Interval)
	defer cancel()

	start := time.Now()

	// Phase 1: ensure the NodePool has enough entries to seed a meaningful
	// BFS. If we're cold, run a find_node warmup walk from bootstraps.
	poolBefore := c.pool.Len()
	if poolBefore < c.opts.MinSeedPool {
		c.warmupFindNode(cycleCtx, c.opts.WarmupNodes)
	}

	// Phase 2: pool-seeded sample_infohashes BFS.
	samples, queried, responses := c.sampleFromPool(cycleCtx)

	// Phase 3: persist discovered infohashes.
	novelRows := 0
	totalRows := 0
	writeCtx, writeCancel := context.WithTimeout(context.Background(), 30*time.Second)
	for hashBytes, source := range samples {
		hashHex := hex.EncodeToString(hashBytes[:])
		inserted, err := db.RecordDiscoveredHash(writeCtx, c.db, hashHex, source)
		if err != nil {
			c.log.Warn("bep51 record", "err", err, "hash", hashHex)
			continue
		}
		totalRows++
		if inserted {
			novelRows++
		}
	}
	writeCancel()
	metrics.AddBEP51Discovered(novelRows)

	c.log.Info("bep51 cycle done",
		"pool_before", poolBefore,
		"pool_after", c.pool.Len(),
		"pool_bep51_known", c.pool.BEP51Count(),
		"visited_nodes", queried,
		"responses", responses,
		"samples_unique", len(samples),
		"rows_written", totalRows,
		"novel", novelRows,
		"elapsed", time.Since(start).String(),
	)
}

// warmupFindNode walks the DHT from bootstraps via find_node, adding every
// returned node to the shared pool. Bounded by `want` nodes visited or
// cycleCtx cancellation.
//
// Used only when the pool is cold; after a few minutes of live scraping
// the pool is populated by the onNodeSeen hook and this runs zero work.
func (c *BEP51Crawler) warmupFindNode(ctx context.Context, want int) {
	bootstraps := BootstrapAddrs()
	if len(bootstraps) == 0 {
		return
	}

	type task struct{ addr *net.UDPAddr }
	var (
		mu         sync.Mutex
		seeded     = make(map[string]bool)
		dispatched int
		frontier   []*net.UDPAddr
	)

	for _, a := range bootstraps {
		seeded[a.String()] = true
		frontier = append(frontier, a)
	}

	jobs := make(chan task, c.opts.Alpha*4)
	var wg sync.WaitGroup
	for i := 0; i < c.opts.Alpha; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				var target NodeID
				_, _ = rand.Read(target[:])
				closer, _, err := c.client.FindNode(ctx, j.addr, target, c.opts.QueryTimeout)
				if err != nil {
					continue
				}
				mu.Lock()
				for _, nn := range closer {
					if nn == nil {
						continue
					}
					key := nn.String()
					if seeded[key] {
						continue
					}
					seeded[key] = true
					// Every FindNode reply also flows through the
					// server's onNodeSeen hook (via KRPC dispatch), so
					// the pool picks up this node for us. We still
					// append to the local frontier for further walking.
					frontier = append(frontier, nn)
				}
				mu.Unlock()
			}
		}()
	}

	go func() {
		defer close(jobs)
		for {
			if ctx.Err() != nil {
				return
			}
			mu.Lock()
			if dispatched >= want {
				mu.Unlock()
				return
			}
			if len(frontier) == 0 {
				mu.Unlock()
				// Short wait for workers to replenish frontier from in-
				// flight replies; exit if no progress after the window.
				select {
				case <-time.After(500 * time.Millisecond):
				case <-ctx.Done():
					return
				}
				mu.Lock()
				if len(frontier) == 0 {
					mu.Unlock()
					return
				}
			}
			n := frontier[0]
			frontier = frontier[1:]
			dispatched++
			mu.Unlock()
			select {
			case jobs <- task{n}:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
}

// sampleFromPool picks MaxNodes addresses from the NodePool and issues
// sample_infohashes at each, collecting returned infohashes. Addresses
// advertised in successful replies are added to the frontier so the walk
// expands beyond the initial seed. Returns (samples, visited, responses).
func (c *BEP51Crawler) sampleFromPool(ctx context.Context) (map[[IDLen]byte]string, int, int) {
	samples := make(map[[IDLen]byte]string)
	var (
		mu         sync.Mutex
		seeded     = make(map[string]bool) // dedup on enqueue
		dispatched int                     // counts jobs actually sent to workers
		frontier   []*net.UDPAddr
		responses  int
	)

	// Initial frontier from the shared pool. Doubled so the BFS has some
	// headroom if many initial picks fail; the inner MaxNodes cap still
	// bounds total work.
	seeds := c.pool.Sample(c.opts.MaxNodes*2, true)
	for _, a := range seeds {
		key := a.String()
		if seeded[key] {
			continue
		}
		seeded[key] = true
		frontier = append(frontier, a)
	}
	if len(frontier) == 0 {
		return samples, 0, 0
	}

	// Random target — BEP 51 responders ignore target in practice, but we
	// compute a single one per cycle to keep query shape compliant.
	var target NodeID
	_, _ = rand.Read(target[:])

	type task struct{ addr *net.UDPAddr }
	jobs := make(chan task, c.opts.Alpha*4)
	var wg sync.WaitGroup
	for i := 0; i < c.opts.Alpha; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				found, closer, _, err := c.client.SampleInfoHashes(ctx, j.addr, target, c.opts.QueryTimeout)
				if err != nil {
					continue
				}
				mu.Lock()
				responses++
				// Any response counts as "this node answered us"; only
				// non-zero samples flip the bep51Known flag so we don't
				// pin nodes that reply with empty on every cycle (likely
				// non-BEP-51 nodes that happened to return y:"r" shape).
				metrics.IncBEP51Sample()
				if len(found) > 0 {
					c.pool.MarkBEP51(j.addr)
				}
				sourceAddr := j.addr.String()
				for _, s := range found {
					if _, ok := samples[s]; ok {
						continue
					}
					samples[s] = sourceAddr
				}
				// Expand frontier with closer nodes — these are fresh
				// BEP 51 candidates. The onNodeSeen hook in dispatch has
				// already added them to the pool too.
				for _, nn := range closer {
					if nn.addr == nil {
						continue
					}
					if !usableIP(nn.addr.IP) || nn.addr.Port == 0 {
						continue
					}
					key := nn.addr.String()
					if seeded[key] {
						continue
					}
					seeded[key] = true
					frontier = append(frontier, nn.addr)
				}
				mu.Unlock()
			}
		}()
	}

	go func() {
		defer close(jobs)
		for {
			if ctx.Err() != nil {
				return
			}
			mu.Lock()
			if dispatched >= c.opts.MaxNodes {
				mu.Unlock()
				return
			}
			if len(frontier) == 0 {
				mu.Unlock()
				select {
				case <-time.After(500 * time.Millisecond):
				case <-ctx.Done():
					return
				}
				mu.Lock()
				if len(frontier) == 0 {
					mu.Unlock()
					return
				}
			}
			n := frontier[0]
			frontier = frontier[1:]
			dispatched++
			mu.Unlock()
			select {
			case jobs <- task{n}:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	return samples, dispatched, responses
}
