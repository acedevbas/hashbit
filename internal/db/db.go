package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/acedevbas/hashbit/internal/trackers"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS infohashes (
    infohash        CHAR(40) PRIMARY KEY,
    source_tracker  TEXT,                           -- optional hint from client (e.g. "rutracker")
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- aggregated view (recomputed every time a tracker returns data):
    seeders         INTEGER,                        -- max() across trackers; NULL if never known
    leechers        INTEGER,
    peer_count      INTEGER,                        -- rutracker's peer count (only set when no seeders known)
    last_update_at  TIMESTAMPTZ,                    -- when aggregate was last recomputed
    -- scheduling:
    next_scrape_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_infohashes_next_scrape ON infohashes (next_scrape_at);
CREATE INDEX IF NOT EXISTS idx_infohashes_source ON infohashes (source_tracker);
CREATE INDEX IF NOT EXISTS idx_infohashes_seeders ON infohashes (seeders);

CREATE TABLE IF NOT EXISTS tracker_state (
    infohash                  CHAR(40) NOT NULL REFERENCES infohashes(infohash) ON DELETE CASCADE,
    tracker                   TEXT NOT NULL,
    seeders                   INTEGER,              -- NULL means "unknown from this tracker"
    leechers                  INTEGER,
    completed                 INTEGER,
    peer_count                INTEGER,
    status                    TEXT NOT NULL,        -- 'ok' | 'not_found' | 'error'
    last_err                  TEXT,
    last_scrape_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_scrape_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consecutive_zero_scrapes  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (infohash, tracker)
);
CREATE INDEX IF NOT EXISTS idx_tracker_state_next ON tracker_state (tracker, next_scrape_at);
CREATE INDEX IF NOT EXISTS idx_tracker_state_infohash ON tracker_state (infohash);
`

// New opens a pgx pool, waits for the DB to become available, and runs migrations.
func New(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 30
	cfg.MinConns = 2
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	// Wait for postgres (container start race)
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := pool.Ping(ctx); err == nil {
			break
		} else if time.Now().After(deadline) {
			return nil, fmt.Errorf("ping timeout: %w", err)
		}
		time.Sleep(time.Second)
	}

	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return pool, nil
}

// AddHashes bulk-inserts infohashes. Existing rows are kept (source_tracker is
// only set on first insert to avoid overwriting). Returns count of rows newly added.
func AddHashes(ctx context.Context, pool *pgxpool.Pool, hashes []HashInput) (int, error) {
	if len(hashes) == 0 {
		return 0, nil
	}
	batch := &pgx.Batch{}
	for _, h := range hashes {
		var src any
		if h.SourceTracker != "" {
			src = h.SourceTracker
		}
		// Seed tracker_state rows for ALL known trackers so each worker has something
		// to schedule. We use next_scrape_at = NOW() so they get picked up immediately.
		batch.Queue(`
            INSERT INTO infohashes (infohash, source_tracker)
            VALUES ($1, $2)
            ON CONFLICT (infohash) DO NOTHING`,
			h.Infohash, src,
		)
		for _, t := range trackers.All {
			batch.Queue(`
                INSERT INTO tracker_state (infohash, tracker, status)
                VALUES ($1, $2, 'pending')
                ON CONFLICT (infohash, tracker) DO NOTHING`,
				h.Infohash, t,
			)
		}
	}
	br := pool.SendBatch(ctx, batch)
	defer br.Close()

	added := 0
	// Results come in batch-submit order: one row per infohash insert, then len(trackers.All) per-tracker inserts.
	for range hashes {
		tag, err := br.Exec()
		if err != nil {
			return added, err
		}
		added += int(tag.RowsAffected())
		for range trackers.All {
			if _, err := br.Exec(); err != nil {
				return added, err
			}
		}
	}
	return added, nil
}

type HashInput struct {
	Infohash      string
	SourceTracker string // "rutor" | "nnm-club" | "kinozal" | "rutracker" | ""
}

// DueHashesForTracker returns up to `limit` infohashes whose next_scrape_at
// has passed for the given tracker, ordered by oldest schedule first.
func DueHashesForTracker(ctx context.Context, pool *pgxpool.Pool, tracker string, limit int) ([]string, error) {
	rows, err := pool.Query(ctx, `
        SELECT infohash FROM tracker_state
        WHERE tracker = $1 AND next_scrape_at <= NOW()
        ORDER BY next_scrape_at
        LIMIT $2`,
		tracker, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// WriteTrackerResults atomically upserts per-tracker state and recomputes the aggregate.
type TrackerResult struct {
	Infohash  string
	Tracker   string
	Seeders   *int32 // nil = unknown
	Leechers  *int32
	Completed *int32
	PeerCount *int32
	Status    string // "ok" | "not_found" | "error"
	Err       string
}

func WriteTrackerResults(
	ctx context.Context,
	pool *pgxpool.Pool,
	results []TrackerResult,
	intervals SchedulerIntervals,
) error {
	if len(results) == 0 {
		return nil
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	updBatch := &pgx.Batch{}
	for _, r := range results {
		updBatch.Queue(`
            UPDATE tracker_state SET
                seeders     = $3,
                leechers    = $4,
                completed   = $5,
                peer_count  = $6,
                status      = $7,
                last_err    = NULLIF($8, ''),
                last_scrape_at = NOW(),
                next_scrape_at = NOW() + (
                    CASE
                        WHEN $7 = 'ok' AND (COALESCE($3, 0) > 0 OR COALESCE($6, 0) > 0)
                             THEN $9::INTERVAL
                        WHEN consecutive_zero_scrapes < 3  THEN $10::INTERVAL
                        WHEN consecutive_zero_scrapes < 10 THEN $11::INTERVAL
                        ELSE                                    $12::INTERVAL
                    END
                ),
                consecutive_zero_scrapes = CASE
                    WHEN $7 = 'ok' AND (COALESCE($3, 0) > 0 OR COALESCE($6, 0) > 0) THEN 0
                    ELSE consecutive_zero_scrapes + 1
                END
            WHERE infohash = $1 AND tracker = $2`,
			r.Infohash, r.Tracker,
			r.Seeders, r.Leechers, r.Completed, r.PeerCount,
			r.Status, r.Err,
			intervals.Alive.String(),
			intervals.Dead1.String(),
			intervals.Dead2.String(),
			intervals.DeadLong.String(),
		)
	}
	br := tx.SendBatch(ctx, updBatch)
	for range results {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return fmt.Errorf("update tracker_state: %w", err)
		}
	}
	if err := br.Close(); err != nil {
		return err
	}

	// Recompute aggregate per affected infohash.
	seen := make(map[string]struct{}, len(results))
	for _, r := range results {
		seen[r.Infohash] = struct{}{}
	}
	aggBatch := &pgx.Batch{}
	for h := range seen {
		aggBatch.Queue(`
            UPDATE infohashes SET
                seeders    = agg.seeders,
                leechers   = agg.leechers,
                peer_count = agg.peers,
                last_update_at = NOW()
            FROM (
                SELECT
                    MAX(seeders)    AS seeders,
                    MAX(leechers)   AS leechers,
                    MAX(peer_count) AS peers
                FROM tracker_state
                WHERE infohash = $1 AND status = 'ok'
            ) AS agg
            WHERE infohash = $1`, h)
	}
	br2 := tx.SendBatch(ctx, aggBatch)
	for range seen {
		if _, err := br2.Exec(); err != nil {
			_ = br2.Close()
			return fmt.Errorf("update infohashes agg: %w", err)
		}
	}
	if err := br2.Close(); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

type SchedulerIntervals struct {
	Alive    time.Duration
	Dead1    time.Duration
	Dead2    time.Duration
	DeadLong time.Duration
}

// --------- Query helpers for API ---------

type HashStats struct {
	Infohash      string
	SourceTracker *string
	Seeders       *int32
	Leechers      *int32
	PeerCount     *int32
	LastUpdateAt  *time.Time
	AddedAt       time.Time
	PerTracker    []TrackerRow
}

type TrackerRow struct {
	Tracker      string
	Seeders      *int32
	Leechers     *int32
	Completed    *int32
	PeerCount    *int32
	Status       string
	LastScrapeAt *time.Time
	LastErr      *string
}

func GetStats(ctx context.Context, pool *pgxpool.Pool, hash string) (*HashStats, error) {
	s := &HashStats{Infohash: hash}
	err := pool.QueryRow(ctx, `
        SELECT source_tracker, seeders, leechers, peer_count, last_update_at, added_at
        FROM infohashes WHERE infohash = $1`, hash,
	).Scan(&s.SourceTracker, &s.Seeders, &s.Leechers, &s.PeerCount, &s.LastUpdateAt, &s.AddedAt)
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(ctx, `
        SELECT tracker, seeders, leechers, completed, peer_count, status, last_scrape_at, last_err
        FROM tracker_state WHERE infohash = $1
        ORDER BY tracker`, hash)
	if err != nil {
		return s, nil
	}
	defer rows.Close()
	for rows.Next() {
		var r TrackerRow
		if err := rows.Scan(&r.Tracker, &r.Seeders, &r.Leechers, &r.Completed, &r.PeerCount, &r.Status, &r.LastScrapeAt, &r.LastErr); err == nil {
			s.PerTracker = append(s.PerTracker, r)
		}
	}
	return s, nil
}

func GetBulkStats(ctx context.Context, pool *pgxpool.Pool, hashes []string) (map[string]*HashStats, error) {
	if len(hashes) == 0 {
		return nil, nil
	}
	rows, err := pool.Query(ctx, `
        SELECT infohash, source_tracker, seeders, leechers, peer_count, last_update_at, added_at
        FROM infohashes WHERE infohash = ANY($1)`, hashes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]*HashStats, len(hashes))
	for rows.Next() {
		s := &HashStats{}
		if err := rows.Scan(&s.Infohash, &s.SourceTracker, &s.Seeders, &s.Leechers, &s.PeerCount, &s.LastUpdateAt, &s.AddedAt); err == nil {
			result[s.Infohash] = s
		}
	}
	return result, nil
}

type GlobalStats struct {
	Total         int64
	Scraped       int64
	WithSeeders   int64
	WithPeersOnly int64
	DueNow        map[string]int64 // tracker → count
}

func GetGlobalStats(ctx context.Context, pool *pgxpool.Pool) (*GlobalStats, error) {
	s := &GlobalStats{DueNow: map[string]int64{}}
	err := pool.QueryRow(ctx, `
        SELECT
            COUNT(*),
            COUNT(*) FILTER (WHERE last_update_at IS NOT NULL),
            COUNT(*) FILTER (WHERE COALESCE(seeders, 0) > 0),
            COUNT(*) FILTER (WHERE COALESCE(seeders, 0) = 0 AND COALESCE(peer_count, 0) > 0)
        FROM infohashes`,
	).Scan(&s.Total, &s.Scraped, &s.WithSeeders, &s.WithPeersOnly)
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(ctx, `
        SELECT tracker, COUNT(*) FROM tracker_state
        WHERE next_scrape_at <= NOW()
        GROUP BY tracker`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t string
			var n int64
			if err := rows.Scan(&t, &n); err == nil {
				s.DueNow[t] = n
			}
		}
	}
	return s, nil
}
