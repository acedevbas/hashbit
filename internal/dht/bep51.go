package dht

// BEP 51 sample_infohashes crawler.
//
// BEP 51 lets a node ask "what infohashes do you know about?" and returns a
// sampled subset (per-node) of its stored hashes. Each compliant node
// responds with ~20 random samples from its storage table, which on a hot
// node can mean thousands of distinct hashes worth of content per hour of
// crawling. Very few hashes in a real BitTorrent swarm collide across
// responders — samples from a well-distributed walk yield mostly fresh
// content.
//
// Crawling strategy:
//   - Generate a random 20-byte `target` (it's purely for protocol shape —
//     BEP 51 responders return samples regardless of target value, per spec).
//   - Seed a short BFS from known bootstrap nodes (or a persistent pool).
//   - At each visited node: issue sample_infohashes; collect the node's
//     samples and its `nodes` field (closer nodes) into the frontier.
//   - Expand until we've visited N nodes or a time budget elapses.
//   - Every discovered hash is UPSERT'ed into `discovered_hashes`. Novel
//     rows increment the Prometheus discovery counter.
//
// Ethics: BEP 51 samples are voluntarily advertised by responding nodes.
// We are not scraping anyone's private data; we are participating in the
// public DHT as BEP 5 envisions. The `discovered_hashes` table is a log
// of public metadata; no content is ever downloaded.
//
// Trade-offs:
//   - We use a dedicated Client so crawler traffic does not starve the
//     scrape pool's UDP socket.
//   - One crawl cycle visits ~maxNodes distinct nodes and takes ~maxNodes
//     * queryTimeout / alpha wall-clock, which at the defaults below caps
//     a cycle at ~1 minute for ~100 nodes.
//   - Cycle cadence is conservative (10m by default) — more frequent
//     crawls hit diminishing returns quickly because BEP 51 samples are
//     drawn without replacement per-node and the same 50 hot nodes
//     account for most of the keyspace.

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
	MaxNodes     int           // unique nodes visited per cycle (default 100)
	Alpha        int           // parallel queries (default 8)
	QueryTimeout time.Duration // per sample_infohashes call (default 2s)
}

// BEP51Crawler orchestrates periodic BEP 51 sample harvest. Construct via
// NewBEP51Crawler, wire a dht.Client for the UDP socket, and Run on a
// background goroutine.
type BEP51Crawler struct {
	client *Client
	pool   *pgxpool.Pool
	log    *slog.Logger
	opts   BEP51CrawlerOptions
}

// NewBEP51Crawler returns a crawler using the supplied Client for its UDP
// traffic. The client must already be active (its read loop started). The
// crawler does not close the client on its own.
func NewBEP51Crawler(client *Client, pool *pgxpool.Pool, log *slog.Logger, opts BEP51CrawlerOptions) *BEP51Crawler {
	if opts.Interval <= 0 {
		opts.Interval = 10 * time.Minute
	}
	if opts.MaxNodes <= 0 {
		opts.MaxNodes = 100
	}
	if opts.Alpha <= 0 {
		opts.Alpha = 8
	}
	if opts.QueryTimeout <= 0 {
		opts.QueryTimeout = 2 * time.Second
	}
	return &BEP51Crawler{
		client: client,
		pool:   pool,
		log:    log,
		opts:   opts,
	}
}

// Run blocks until ctx is cancelled, running one crawl cycle per Interval.
// A cycle is bounded internally so overruns don't skew the next schedule.
func (c *BEP51Crawler) Run(ctx context.Context) {
	c.log.Info("bep51 crawler starting",
		"interval", c.opts.Interval,
		"max_nodes", c.opts.MaxNodes,
		"alpha", c.opts.Alpha,
	)
	// Initial delay before the first cycle so we don't hammer the DHT during
	// container start-up when many sockets are still warming their routing
	// tables.
	timer := time.NewTimer(30 * time.Second)
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

// runCycle performs one BFS-bounded walk and records every sample. A cycle
// is hard-capped at Interval so it cannot eat the next one.
func (c *BEP51Crawler) runCycle(ctx context.Context) {
	cycleCtx, cancel := context.WithTimeout(ctx, c.opts.Interval)
	defer cancel()

	start := time.Now()
	var target NodeID
	if _, err := rand.Read(target[:]); err != nil {
		c.log.Warn("bep51 target rand", "err", err)
		return
	}

	// Frontier: nodes we know about but haven't queried yet. seen tracks
	// addresses we've already enqueued to avoid re-queueing through the
	// same address via multiple parents.
	var (
		mu        sync.Mutex
		frontier  []node
		seen      = make(map[string]bool)
		queried   = make(map[string]bool)
		samples   = make(map[[IDLen]byte]string) // hash -> source addr
		novelRows = 0
		totalRows = 0
		responses = 0
	)

	bootstraps := BootstrapAddrs()
	for _, a := range bootstraps {
		key := a.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		frontier = append(frontier, node{addr: a})
	}
	if len(frontier) == 0 {
		c.log.Warn("bep51 crawler: no bootstrap resolved")
		return
	}

	// Worker pool that drains the frontier. Using Alpha workers concurrently
	// strikes a balance: too few makes cycles slow, too many saturates our
	// UDP socket and forces remote rate-limits.
	type job struct{ n node }
	jobs := make(chan job, c.opts.Alpha*4)
	var wg sync.WaitGroup
	for i := 0; i < c.opts.Alpha; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				samplesFound, closer, _, err := c.client.SampleInfoHashes(cycleCtx, j.n.addr, target, c.opts.QueryTimeout)
				if err != nil {
					continue
				}
				mu.Lock()
				responses++
				metrics.IncBEP51Sample()
				sourceAddr := j.n.addr.String()
				for _, s := range samplesFound {
					if _, ok := samples[s]; ok {
						continue
					}
					samples[s] = sourceAddr
				}
				// Expand frontier with closer nodes we haven't queued yet.
				for _, nn := range closer {
					if nn.addr == nil {
						continue
					}
					if !usableIP(nn.addr.IP) || nn.addr.Port == 0 {
						continue
					}
					key := nn.addr.String()
					if seen[key] {
						continue
					}
					if len(seen)-len(queried) >= c.opts.MaxNodes*2 {
						// Avoid unbounded memory growth on well-connected
						// parents. seen grows ~2x visited before we stop
						// expanding.
						continue
					}
					seen[key] = true
					frontier = append(frontier, nn)
				}
				mu.Unlock()
			}
		}()
	}

	// Dispatcher: pulls from frontier, pushes to workers, stops when we've
	// visited MaxNodes or the frontier is empty.
	go func() {
		defer close(jobs)
		for {
			if cycleCtx.Err() != nil {
				return
			}
			mu.Lock()
			if len(queried) >= c.opts.MaxNodes {
				mu.Unlock()
				return
			}
			if len(frontier) == 0 {
				mu.Unlock()
				// Give workers a moment to repopulate frontier from their
				// replies; if after 500ms there's still nothing we're done.
				select {
				case <-time.After(500 * time.Millisecond):
				case <-cycleCtx.Done():
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
			key := n.addr.String()
			if queried[key] {
				mu.Unlock()
				continue
			}
			queried[key] = true
			mu.Unlock()
			select {
			case jobs <- job{n}:
			case <-cycleCtx.Done():
				return
			}
		}
	}()

	wg.Wait()

	// Persist collected samples. Doing it after the crawl keeps the UDP
	// read-path latency clean; a few thousand UPSERTs is fast even on a
	// cold Postgres instance.
	writeCtx, writeCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer writeCancel()
	for hashBytes, source := range samples {
		hashHex := hex.EncodeToString(hashBytes[:])
		inserted, err := db.RecordDiscoveredHash(writeCtx, c.pool, hashHex, source)
		if err != nil {
			c.log.Warn("bep51 record", "err", err, "hash", hashHex)
			continue
		}
		totalRows++
		if inserted {
			novelRows++
		}
	}
	metrics.AddBEP51Discovered(novelRows)

	c.log.Info("bep51 cycle done",
		"visited_nodes", len(queried),
		"responses", responses,
		"samples_unique", len(samples),
		"rows_written", totalRows,
		"novel", novelRows,
		"elapsed", time.Since(start).String(),
	)
}

// unused guard for net.UDPAddr references from other build flavors.
var _ = net.UDPAddr{}
