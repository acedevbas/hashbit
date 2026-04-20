package db

import (
	"context"
	"fmt"
	"time"

	"github.com/acedevbas/hashbit/internal/trackers"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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

-- Temporal accumulation: current seeders/leechers/peer_count reflect the
-- instantaneous MAX across trackers and decay when peers go offline.
-- Peaks preserve the historical high-water mark so swarm health signal
-- survives churn. last_nonzero_at captures the most recent moment we
-- observed a live swarm, which is a stronger liveness signal than
-- last_update_at (which ticks on every scrape, even zero ones).
-- Idempotent: ADD COLUMN IF NOT EXISTS works for both fresh installs and upgrades.
ALTER TABLE infohashes ADD COLUMN IF NOT EXISTS peak_seeders INTEGER;
ALTER TABLE infohashes ADD COLUMN IF NOT EXISTS peak_leechers INTEGER;
ALTER TABLE infohashes ADD COLUMN IF NOT EXISTS peak_peer_count INTEGER;
ALTER TABLE infohashes ADD COLUMN IF NOT EXISTS last_nonzero_at TIMESTAMPTZ;

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

-- Backfill tracker_state rows for the 'public' aggregator so existing installs
-- start scheduling public-scrape for hashes added before this tracker existed.
-- NOT EXISTS form is cheaper than INSERT ... ON CONFLICT DO NOTHING on wide tables.
INSERT INTO tracker_state (infohash, tracker, status)
SELECT i.infohash, 'public', 'pending'
FROM infohashes i
WHERE NOT EXISTS (
    SELECT 1 FROM tracker_state ts
    WHERE ts.infohash = i.infohash AND ts.tracker = 'public'
);

-- Same backfill for the DHT BEP 33 scraper.
INSERT INTO tracker_state (infohash, tracker, status)
SELECT i.infohash, 'dht', 'pending'
FROM infohashes i
WHERE NOT EXISTS (
    SELECT 1 FROM tracker_state ts
    WHERE ts.infohash = i.infohash AND ts.tracker = 'dht'
);

-- Same backfill for the WebTorrent WSS scraper.
INSERT INTO tracker_state (infohash, tracker, status)
SELECT i.infohash, 'webtorrent', 'pending'
FROM infohashes i
WHERE NOT EXISTS (
    SELECT 1 FROM tracker_state ts
    WHERE ts.infohash = i.infohash AND ts.tracker = 'webtorrent'
);

-- Passive DHT cache: (infohash, peer) pairs harvested from incoming
-- announce_peer KRPC queries. This is append-heavy and time-windowed — the
-- janitor deletes rows older than 2*PassivePeerTTL, keeping the table bounded
-- regardless of swarm churn. PK collapses duplicate observations; last_seen
-- bumps on every re-observation so "recent" queries are cheap.
CREATE TABLE IF NOT EXISTS dht_passive_peers (
    infohash   CHAR(40) NOT NULL,
    peer       TEXT NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (infohash, peer)
);
-- Primary read path: "recent peers for this infohash". The DESC order on
-- last_seen matches the query in FreshPassivePeers so it's served straight
-- from the index without an extra sort.
CREATE INDEX IF NOT EXISTS idx_dht_passive_recent
    ON dht_passive_peers (infohash, last_seen DESC);
-- Janitor sweep index: deletion by age crosses all hashes, so a
-- last_seen-only index is materially faster than the composite above.
CREATE INDEX IF NOT EXISTS idx_dht_passive_last_seen
    ON dht_passive_peers (last_seen);

-- BEP 51 sample_infohashes discovery log. Separate from infohashes because
-- these are candidate hashes we haven't committed to scraping yet — they
-- may be spam, private-torrent shards, or genuinely interesting content.
-- A downstream process (or the operator) promotes rows into infohashes
-- on their own schedule.
CREATE TABLE IF NOT EXISTS discovered_hashes (
    infohash     CHAR(40) PRIMARY KEY,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    seen_count   INTEGER     NOT NULL DEFAULT 1,
    source_node  TEXT                                     -- IP:port of first reporting node
);
CREATE INDEX IF NOT EXISTS idx_discovered_last_seen ON discovered_hashes (last_seen);
CREATE INDEX IF NOT EXISTS idx_discovered_first_seen ON discovered_hashes (first_seen);
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
		// Once-alive hashes (peak_peer_count > 0) get a compressed backoff
		// progression — we've seen them host a live swarm before, so
		// consecutive zeros are more likely to be variance (swarm churn
		// during our scrape window, NAT issues, momentary DHT partition)
		// than a permanently-dead hash. Compressed ladder: alive→10m
		// through <5 zeros, then dead1 through <15, then dead2 through <30,
		// finally fall back to dead_long. Hashes that have never been seen
		// alive still go through the original 3/10 ladder so we don't churn
		// on permanently-dead hashes that were added cold.
		//
		// Join via scalar subquery on the PK — planner uses the infohashes
		// pkey index, ~free compared to the UPDATE itself.
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
                        WHEN COALESCE((SELECT peak_peer_count FROM infohashes WHERE infohash = $1), 0) > 0 THEN
                            CASE
                                WHEN consecutive_zero_scrapes < 5  THEN INTERVAL '10 minutes'
                                WHEN consecutive_zero_scrapes < 15 THEN $10::INTERVAL
                                WHEN consecutive_zero_scrapes < 30 THEN $11::INTERVAL
                                ELSE                                    $12::INTERVAL
                            END
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
		// Peaks use GREATEST(existing, incoming) with COALESCE so the first
		// non-NULL observation seeds the peak. last_nonzero_at is only bumped
		// when the swarm is currently alive, giving callers a reliable
		// "was seen alive at …" timestamp independent of scrape cadence.
		aggBatch.Queue(`
            UPDATE infohashes SET
                seeders    = agg.seeders,
                leechers   = agg.leechers,
                peer_count = agg.peers,
                peak_seeders    = GREATEST(COALESCE(peak_seeders, 0),    COALESCE(agg.seeders, 0)),
                peak_leechers   = GREATEST(COALESCE(peak_leechers, 0),   COALESCE(agg.leechers, 0)),
                peak_peer_count = GREATEST(COALESCE(peak_peer_count, 0), COALESCE(agg.peers, 0)),
                last_update_at  = NOW(),
                last_nonzero_at = CASE
                    WHEN COALESCE(agg.seeders, 0) > 0 OR COALESCE(agg.peers, 0) > 0 THEN NOW()
                    ELSE last_nonzero_at
                END
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
	// Historical peaks — survive swarm churn so a torrent that was
	// healthy last week is still recognizable today.
	PeakSeeders   *int32
	PeakLeechers  *int32
	PeakPeerCount *int32
	LastNonzeroAt *time.Time
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
        SELECT source_tracker, seeders, leechers, peer_count, last_update_at, added_at,
               peak_seeders, peak_leechers, peak_peer_count, last_nonzero_at
        FROM infohashes WHERE infohash = $1`, hash,
	).Scan(&s.SourceTracker, &s.Seeders, &s.Leechers, &s.PeerCount, &s.LastUpdateAt, &s.AddedAt,
		&s.PeakSeeders, &s.PeakLeechers, &s.PeakPeerCount, &s.LastNonzeroAt)
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
        SELECT infohash, source_tracker, seeders, leechers, peer_count, last_update_at, added_at,
               peak_seeders, peak_leechers, peak_peer_count, last_nonzero_at
        FROM infohashes WHERE infohash = ANY($1)`, hashes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]*HashStats, len(hashes))
	for rows.Next() {
		s := &HashStats{}
		if err := rows.Scan(&s.Infohash, &s.SourceTracker, &s.Seeders, &s.Leechers, &s.PeerCount, &s.LastUpdateAt, &s.AddedAt,
			&s.PeakSeeders, &s.PeakLeechers, &s.PeakPeerCount, &s.LastNonzeroAt); err == nil {
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

// --------- Passive DHT peer cache ---------

// RecordPassivePeer UPSERTs one (infohash, peer) observation, bumping
// last_seen to NOW() on conflict. Idempotent and cheap; the caller (the
// passive DHT write-behind batcher) funnels many of these per second.
func RecordPassivePeer(ctx context.Context, pool *pgxpool.Pool, infohash, peer string) error {
	_, err := pool.Exec(ctx, `
        INSERT INTO dht_passive_peers (infohash, peer)
        VALUES ($1, $2)
        ON CONFLICT (infohash, peer) DO UPDATE SET last_seen = NOW()`,
		infohash, peer,
	)
	return err
}

// FreshPassivePeers returns peers observed within `within` for `infohash`,
// newest first, capped at `limit`. Served from idx_dht_passive_recent without
// an extra sort pass. Returns an empty slice for cold/unknown hashes.
func FreshPassivePeers(ctx context.Context, pool *pgxpool.Pool, infohash string, within time.Duration, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 200
	}
	cutoff := time.Now().Add(-within)
	rows, err := pool.Query(ctx, `
        SELECT peer FROM dht_passive_peers
        WHERE infohash = $1 AND last_seen >= $2
        ORDER BY last_seen DESC
        LIMIT $3`,
		infohash, cutoff, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0, limit)
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return out, err
		}
		out = append(out, p)
	}
	return out, nil
}

// RecordDiscoveredHash UPSERTs one BEP 51 sample observation. Returns true
// if the row was new (infohash had never been seen before this call); false
// if it was a repeat observation. Used by the crawler to increment metrics
// for "novel discoveries" separately from "reaffirmations".
func RecordDiscoveredHash(ctx context.Context, pool *pgxpool.Pool, infohash, sourceNode string) (bool, error) {
	// xmax = 0 in the RETURNING clause signals a fresh INSERT (not an UPDATE
	// caused by the ON CONFLICT branch), letting us count "first seen" vs
	// "already known" without a prior SELECT.
	var inserted bool
	err := pool.QueryRow(ctx, `
        INSERT INTO discovered_hashes (infohash, source_node)
        VALUES ($1, $2)
        ON CONFLICT (infohash) DO UPDATE
            SET last_seen = NOW(),
                seen_count = discovered_hashes.seen_count + 1
        RETURNING (xmax = 0)`,
		infohash, sourceNode,
	).Scan(&inserted)
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// PassivePeersExpireOlderThan deletes observations older than `cutoff`.
// Run periodically (the passive DHT janitor) to keep the table bounded.
// Returns the number of rows deleted for logging/metrics.
func PassivePeersExpireOlderThan(ctx context.Context, pool *pgxpool.Pool, cutoff time.Time) (int64, error) {
	tag, err := pool.Exec(ctx, `
        DELETE FROM dht_passive_peers WHERE last_seen < $1`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
