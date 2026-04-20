// Package metrics exposes the service's Prometheus registry.
//
// One registry per process — every subsystem publishes into it, and the API
// router serves it at /metrics. The metric shapes are deliberately broad
// (counters for hot paths, histograms for latency, a couple of gauges that
// a background sampler refreshes from Postgres) so a single Grafana board
// can drive all alerting.
//
// Design notes:
//   - No global package-level mutable state besides the registry itself; all
//     metric variables are local to this package and accessed via exported
//     functions so call-sites keep working if we rename labels later.
//   - Counter labels are bounded (tracker name, status) — unbounded labels
//     would explode Prometheus cardinality within a day on a 600k-hash DB.
//   - The gauge sampler runs on its own goroutine at a slow cadence because
//     the underlying SELECT COUNT(*) scans are wall-clock expensive on a
//     table that size; the freshness penalty (~30s) is acceptable for
//     dashboards.
package metrics

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry is the single Prometheus registry used by the service. Exported so
// tests can swap it in if needed; production code should use the Handler()
// helper instead of referring to this directly.
var Registry = prometheus.NewRegistry()

var (
	// Scrape tick outcomes, labelled by tracker + outcome bucket.
	scrapesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hashbit_scrapes_total",
			Help: "Per-tracker scrape tick outcomes aggregated from worker ticks.",
		},
		[]string{"tracker", "outcome"}, // outcome: ok | not_found | error
	)

	// Scrape tick duration. Buckets span 50ms (cheap HTTP scrape) to 3min
	// (DHT batch with rescue) so both extremes land in the histogram.
	scrapeDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "hashbit_scrape_duration_seconds",
			Help:    "Distribution of per-tick scrape latencies per tracker.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 180},
		},
		[]string{"tracker"},
	)

	// DHT-specific counters. Kept separate from scrapesTotal because the DHT
	// pipeline has an internal branch (rescue) we want to see independently.
	dhtRescueTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hashbit_dht_rescue_total",
			Help: "Anacrolix rescue-lookup invocations by outcome.",
		},
		[]string{"outcome"}, // peers | bep33 | empty | error
	)

	dhtPeersFoundTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hashbit_dht_peers_found_total",
			Help: "Cumulative peers returned by active DHT lookups across all clients.",
		},
	)

	dhtBEP33RespondersTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hashbit_dht_bep33_responders_total",
			Help: "Cumulative BEP 33-capable DHT nodes that replied across all lookups.",
		},
	)

	// Passive DHT observer.
	passiveQueriesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hashbit_passive_queries_total",
			Help: "Incoming KRPC queries answered by the passive DHT node.",
		},
	)
	passiveAnnouncesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hashbit_passive_announces_total",
			Help: "Observed announce_peer KRPC queries (useful swarm membership).",
		},
	)

	// BEP 51 discovery.
	bep51HashesDiscovered = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hashbit_bep51_hashes_discovered_total",
			Help: "Infohashes newly discovered via BEP 51 sample_infohashes crawl.",
		},
	)
	bep51Samples = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hashbit_bep51_samples_total",
			Help: "Successful BEP 51 sample_infohashes responses received.",
		},
	)

	// DB-derived gauges. Refreshed by the sampler goroutine.
	hashesTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "hashbit_hashes_total",
			Help: "Total number of infohashes tracked in the database.",
		},
	)
	hashesWithSeeders = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "hashbit_hashes_with_seeders",
			Help: "Infohashes whose latest aggregate has seeders > 0 (instantaneously live).",
		},
	)
	hashesEverSeeded = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "hashbit_hashes_ever_seeded",
			Help: "Infohashes whose historical peak_seeders > 0 (ever observed alive).",
		},
	)
	hashesScraped = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "hashbit_hashes_scraped_total",
			Help: "Infohashes that have been scraped at least once (last_update_at NOT NULL).",
		},
	)
	passivePeersTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "hashbit_passive_peers_rows",
			Help: "Rows currently held in the passive DHT peer cache (bounded by janitor).",
		},
	)
	passiveUniqueHashes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "hashbit_passive_unique_hashes",
			Help: "Distinct infohashes observed in the passive DHT cache.",
		},
	)
	dueNowByTracker = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "hashbit_due_now_by_tracker",
			Help: "Number of tracker_state rows whose next_scrape_at has already passed.",
		},
		[]string{"tracker"},
	)
)

func init() {
	Registry.MustRegister(
		scrapesTotal,
		scrapeDurationSeconds,
		dhtRescueTotal,
		dhtPeersFoundTotal,
		dhtBEP33RespondersTotal,
		passiveQueriesTotal,
		passiveAnnouncesTotal,
		bep51HashesDiscovered,
		bep51Samples,
		hashesTotal,
		hashesWithSeeders,
		hashesEverSeeded,
		hashesScraped,
		passivePeersTotal,
		passiveUniqueHashes,
		dueNowByTracker,
	)
	// Go runtime + process metrics come for free; include them so CPU/memory
	// trends show up on the same dashboard as the application counters.
	Registry.MustRegister(prometheus.NewGoCollector())
	Registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
}

// Handler returns the HTTP handler that serves /metrics in Prometheus text
// format. Wire this into the router without an auth middleware — Prometheus
// commonly scrapes without auth from inside the private network.
func Handler() http.Handler {
	return promhttp.HandlerFor(Registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	})
}

// ObserveScrapeTick records one worker-tick's outcome distribution. Counts
// are added atomically per outcome bucket; the observed duration is shared
// across all rows in the batch because each tick produces one wall-clock
// measurement regardless of batch size.
func ObserveScrapeTick(tracker string, ok, notFound, errs int, duration time.Duration) {
	scrapeDurationSeconds.WithLabelValues(tracker).Observe(duration.Seconds())
	if ok > 0 {
		scrapesTotal.WithLabelValues(tracker, "ok").Add(float64(ok))
	}
	if notFound > 0 {
		scrapesTotal.WithLabelValues(tracker, "not_found").Add(float64(notFound))
	}
	if errs > 0 {
		scrapesTotal.WithLabelValues(tracker, "error").Add(float64(errs))
	}
}

// IncDHTRescue tags one rescue-lookup outcome. outcome is one of:
//
//   - "peers"  — found raw peers
//   - "bep33"  — found BEP 33 responders (no raw peers)
//   - "empty"  — ran but returned nothing
//   - "error"  — failed before returning anything useful
func IncDHTRescue(outcome string) {
	dhtRescueTotal.WithLabelValues(outcome).Inc()
}

// AddDHTPeers increments the cumulative count of peers returned by active
// DHT lookups. Called once per scrape tick after merging per-client results.
func AddDHTPeers(n int) {
	if n > 0 {
		dhtPeersFoundTotal.Add(float64(n))
	}
}

// AddDHTBEP33Responders increments the cumulative count of BEP 33-capable
// responders. The counter is monotonic and cross-hash — it is not meaningful
// to divide by unique hashes without a query on top of it.
func AddDHTBEP33Responders(n int) {
	if n > 0 {
		dhtBEP33RespondersTotal.Add(float64(n))
	}
}

// IncPassiveQuery / IncPassiveAnnounce are called from the passive KRPC
// read loop.
func IncPassiveQuery()    { passiveQueriesTotal.Inc() }
func IncPassiveAnnounce() { passiveAnnouncesTotal.Inc() }

// BEP 51 discovery counters.
func IncBEP51Sample()               { bep51Samples.Inc() }
func AddBEP51Discovered(n int) {
	if n > 0 {
		bep51HashesDiscovered.Add(float64(n))
	}
}

// StartGaugeSampler runs the DB-backed gauge refresher in the background.
// Values refresh every `interval` (recommended 30-60s). On context cancel the
// goroutine exits — callers do not need to wait on it, stale gauges are fine
// during shutdown.
func StartGaugeSampler(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		// Sample once immediately so Prometheus sees non-zero gauges from the
		// first scrape; otherwise dashboards show a gap between process start
		// and the first tick.
		sampleGauges(ctx, pool, log)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sampleGauges(ctx, pool, log)
			}
		}
	}()
}

func sampleGauges(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	// Use a generous per-query deadline so one slow sample does not stall the
	// sampler loop forever. 10s is enough for a COUNT(*) on 1-2M rows with
	// an index; beyond that we assume something is wrong and bail.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var total, withSeed, everSeed, scraped int64
	err := pool.QueryRow(ctx, `
        SELECT
            COUNT(*),
            COUNT(*) FILTER (WHERE COALESCE(seeders, 0) > 0),
            COUNT(*) FILTER (WHERE COALESCE(peak_seeders, 0) > 0),
            COUNT(*) FILTER (WHERE last_update_at IS NOT NULL)
        FROM infohashes`).Scan(&total, &withSeed, &everSeed, &scraped)
	if err == nil {
		hashesTotal.Set(float64(total))
		hashesWithSeeders.Set(float64(withSeed))
		hashesEverSeeded.Set(float64(everSeed))
		hashesScraped.Set(float64(scraped))
	} else {
		log.Warn("metrics: hashes gauge query failed", "err", err)
	}

	var passiveRows, passiveHashes int64
	if err := pool.QueryRow(ctx, `
        SELECT COUNT(*), COUNT(DISTINCT infohash) FROM dht_passive_peers`).
		Scan(&passiveRows, &passiveHashes); err == nil {
		passivePeersTotal.Set(float64(passiveRows))
		passiveUniqueHashes.Set(float64(passiveHashes))
	} else {
		log.Warn("metrics: passive gauge query failed", "err", err)
	}

	rows, err := pool.Query(ctx, `
        SELECT tracker, COUNT(*) FROM tracker_state
        WHERE next_scrape_at <= NOW()
        GROUP BY tracker`)
	if err != nil {
		log.Warn("metrics: due_now query failed", "err", err)
		return
	}
	defer rows.Close()
	// Reset: trackers that dropped to zero would otherwise carry the previous
	// tick's value forever. Simpler than tracking "known" labels separately.
	dueNowByTracker.Reset()
	for rows.Next() {
		var t string
		var n int64
		if err := rows.Scan(&t, &n); err == nil {
			dueNowByTracker.WithLabelValues(t).Set(float64(n))
		}
	}
}
