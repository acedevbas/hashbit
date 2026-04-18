// Package scheduler runs per-tracker background workers.
// Each worker:
//   - periodically pulls a batch of due hashes for its tracker from the DB,
//   - queries the tracker (scrape or announce depending on tracker type),
//   - writes results + reschedules next scrape time with exponential backoff.
//
// Workers are independent: one tracker being slow/broken does not affect others.
package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	"github.com/acedevbas/hashbit/internal/config"
	"github.com/acedevbas/hashbit/internal/db"
	"github.com/acedevbas/hashbit/internal/trackers"
)

// Scraper is the tracker-specific interface each worker speaks to.
type Scraper interface {
	Scrape(ctx context.Context, hashes []string) map[string]trackers.Response
}

// Worker runs one tracker's scrape/announce loop.
type Worker struct {
	Name      string // one of trackers.*
	DB        *pgxpool.Pool
	Scraper   Scraper
	Log       *slog.Logger
	BatchSize int
	Tick      time.Duration
	Limiter   *rate.Limiter // optional; nil = no rate limit
	Intervals db.SchedulerIntervals
}

func (w *Worker) Run(ctx context.Context) {
	w.Log.Info("worker starting",
		"tracker", w.Name,
		"batch_size", w.BatchSize,
		"tick", w.Tick,
	)
	t := time.NewTicker(w.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			w.Log.Info("worker stopping", "tracker", w.Name)
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	hashes, err := db.DueHashesForTracker(ctx, w.DB, w.Name, w.BatchSize)
	if err != nil {
		w.Log.Error("fetch due hashes", "tracker", w.Name, "err", err)
		return
	}
	if len(hashes) == 0 {
		return
	}

	if w.Limiter != nil {
		// Reserve tokens up-front — announce workers are rate-limited per-request.
		// Scrape workers batch, so one batch = one token.
		if err := w.Limiter.Wait(ctx); err != nil {
			return
		}
	}

	start := time.Now()
	responses := w.Scraper.Scrape(ctx, hashes)
	took := time.Since(start)

	results := make([]db.TrackerResult, 0, len(hashes))
	var ok, notFound, errs int
	for _, h := range hashes {
		r := responses[h]
		tr := db.TrackerResult{Infohash: h, Tracker: w.Name}
		switch r.Status {
		case trackers.StatusOK:
			ok++
			tr.Status = "ok"
			tr.Seeders = nilableInt32(r.Result.Seeders)
			tr.Leechers = nilableInt32(r.Result.Leechers)
			tr.Completed = nilableInt32(r.Result.Completed)
			tr.PeerCount = nilableInt32(r.Result.PeerCount)
		case trackers.StatusNotFound:
			notFound++
			tr.Status = "not_found"
		case trackers.StatusError:
			errs++
			tr.Status = "error"
			tr.Err = r.Err
		}
		results = append(results, tr)
	}

	if err := db.WriteTrackerResults(ctx, w.DB, results, w.Intervals); err != nil {
		w.Log.Error("write results", "tracker", w.Name, "err", err)
		return
	}
	w.Log.Info("tick done",
		"tracker", w.Name,
		"count", len(hashes),
		"ok", ok, "not_found", notFound, "errors", errs,
		"took", took.String(),
	)
}

func nilableInt32(v int32) *int32 {
	if v < 0 {
		return nil
	}
	return &v
}

// ConfigureWorker is a helper for main to wire up a worker with a given rate limit.
// rps == 0 means "no limit".
func ConfigureWorker(name string, scraper Scraper, cfg *config.Config, pool *pgxpool.Pool, log *slog.Logger, batchSize int, tick time.Duration, rps int) *Worker {
	var lim *rate.Limiter
	if rps > 0 {
		lim = rate.NewLimiter(rate.Limit(rps), rps*2)
	}
	return &Worker{
		Name:      name,
		DB:        pool,
		Scraper:   scraper,
		Log:       log,
		BatchSize: batchSize,
		Tick:      tick,
		Limiter:   lim,
		Intervals: db.SchedulerIntervals{
			Alive:    cfg.IntervalAlive,
			Dead1:    cfg.IntervalDead1,
			Dead2:    cfg.IntervalDead2,
			DeadLong: cfg.IntervalDeadLong,
		},
	}
}
