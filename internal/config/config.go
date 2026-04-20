package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Core
	DatabaseURL string
	HTTPAddr    string
	UserAgent   string

	// Auth (simple bearer token)
	APIToken string

	// Per-tracker batch sizes and rate limits
	RutorBatchSize    int
	NNMBatchSize      int
	PublicBatchSize   int
	PublicConcurrency int  // max concurrent endpoint flows inside one public scrape
	PublicAnnounce    bool // also do BEP 15 announce alongside scrape — more peers, slower tick

	// Auto-refresh of public tracker endpoint lists from ngosang/trackerslist.
	// Refresh is 0 = disabled (stick with bundled defaults); otherwise a
	// background goroutine pulls updated lists every interval.
	PublicRefreshInterval time.Duration
	PublicRefreshHTTPURL  string
	PublicRefreshUDPURL   string
	DHTBatchSize          int
	DHTConcurrency        int           // max concurrent ops across the whole DHT pool per tick
	DHTLookupTimeout      time.Duration // budget for one hash on one client
	DHTAlpha              int           // Kademlia parallelism factor
	DHTClients            int           // DHT pool size (distinct node ids / sockets)
	KinozalRateLimit      int           // req/sec
	RutrackerRateLimit    int           // req/sec

	// WebTorrent WSS scraper sizing.
	WebTorrentBatchSize   int
	WebTorrentConcurrency int

	// Per-tracker tick intervals (how often the worker wakes up to process a chunk)
	ScrapeTick     time.Duration
	AnnounceTick   time.Duration
	TrackerTimeout time.Duration

	// Scheduler intervals
	IntervalAlive    time.Duration
	IntervalDead1    time.Duration // first few zeros
	IntervalDead2    time.Duration // 3-10 zeros
	IntervalDeadLong time.Duration // >10 zeros
	OnDemandTimeout  time.Duration

	// Kinozal passkey
	KinozalUK string

	// Passive DHT node ("Sybil-lite"): answers incoming KRPC queries on a
	// stable UDP port and harvests observed announce_peer into a persistent
	// cache. Running 24/7 gradually turns the cache into a snapshot of the
	// public swarm for any hash popular enough to route through us.
	DHTPassiveEnabled         bool
	DHTPassivePort            int
	DHTPassivePeerTTL         time.Duration
	DHTPassiveJanitorInterval time.Duration
	DHTPassiveMaxPerHash      int
}

func Load() (*Config, error) {
	c := &Config{
		DatabaseURL: getenv("DATABASE_URL", "postgres://tracker:tracker@db:5432/tracker?sslmode=disable"),
		HTTPAddr:    getenv("HTTP_ADDR", ":8080"),
		UserAgent:   getenv("USER_AGENT", "uTorrent/3.5.5"),
		APIToken:    strings.TrimSpace(os.Getenv("API_TOKEN")),
		KinozalUK:   strings.TrimSpace(os.Getenv("KINOZAL_UK")),
	}

	var err error
	if c.RutorBatchSize, err = atoi("RUTOR_BATCH_SIZE", "300"); err != nil {
		return nil, err
	}
	if c.NNMBatchSize, err = atoi("NNM_BATCH_SIZE", "300"); err != nil {
		return nil, err
	}
	if c.PublicBatchSize, err = atoi("PUBLIC_BATCH_SIZE", "500"); err != nil {
		return nil, err
	}
	if c.PublicConcurrency, err = atoi("PUBLIC_CONCURRENCY", "32"); err != nil {
		return nil, err
	}
	c.PublicAnnounce = strings.EqualFold(getenv("PUBLIC_ANNOUNCE", "1"), "1") ||
		strings.EqualFold(getenv("PUBLIC_ANNOUNCE", "1"), "true")
	// Default 6h refresh balances freshness vs upstream GitHub etiquette.
	// Set to 0 to fully disable external fetches (e.g. air-gapped deploys).
	if c.PublicRefreshInterval, err = dur("PUBLIC_REFRESH_INTERVAL", "6h"); err != nil {
		return nil, err
	}
	c.PublicRefreshHTTPURL = getenv("PUBLIC_REFRESH_URL_HTTP",
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_http.txt")
	c.PublicRefreshUDPURL = getenv("PUBLIC_REFRESH_URL_UDP",
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_udp.txt")
	if c.DHTBatchSize, err = atoi("DHT_BATCH_SIZE", "100"); err != nil {
		return nil, err
	}
	if c.DHTConcurrency, err = atoi("DHT_CONCURRENCY", "64"); err != nil {
		return nil, err
	}
	if c.DHTAlpha, err = atoi("DHT_ALPHA", "8"); err != nil {
		return nil, err
	}
	if c.DHTClients, err = atoi("DHT_CLIENTS", "4"); err != nil {
		return nil, err
	}
	if c.DHTLookupTimeout, err = dur("DHT_LOOKUP_TIMEOUT", "12s"); err != nil {
		return nil, err
	}
	if c.KinozalRateLimit, err = atoi("KINOZAL_RPS", "5"); err != nil {
		return nil, err
	}
	if c.RutrackerRateLimit, err = atoi("RUTRACKER_RPS", "5"); err != nil {
		return nil, err
	}
	if c.WebTorrentBatchSize, err = atoi("WEBTORRENT_BATCH_SIZE", "50"); err != nil {
		return nil, err
	}
	if c.WebTorrentConcurrency, err = atoi("WEBTORRENT_CONCURRENCY", "8"); err != nil {
		return nil, err
	}

	if c.ScrapeTick, err = dur("SCRAPE_TICK", "15s"); err != nil {
		return nil, err
	}
	if c.AnnounceTick, err = dur("ANNOUNCE_TICK", "1s"); err != nil {
		return nil, err
	}
	if c.TrackerTimeout, err = dur("TRACKER_TIMEOUT", "15s"); err != nil {
		return nil, err
	}
	if c.IntervalAlive, err = dur("INTERVAL_ALIVE", "30m"); err != nil {
		return nil, err
	}
	if c.IntervalDead1, err = dur("INTERVAL_DEAD1", "1h"); err != nil {
		return nil, err
	}
	if c.IntervalDead2, err = dur("INTERVAL_DEAD2", "6h"); err != nil {
		return nil, err
	}
	if c.IntervalDeadLong, err = dur("INTERVAL_DEAD_LONG", "24h"); err != nil {
		return nil, err
	}
	if c.OnDemandTimeout, err = dur("ON_DEMAND_TIMEOUT", "10s"); err != nil {
		return nil, err
	}

	// Passive DHT node. Defaults: enabled, port 6881 (BitTorrent standard —
	// peers remember our endpoint across restarts because it is stable).
	c.DHTPassiveEnabled = strings.EqualFold(getenv("DHT_PASSIVE_ENABLED", "1"), "1") ||
		strings.EqualFold(getenv("DHT_PASSIVE_ENABLED", "1"), "true")
	if c.DHTPassivePort, err = atoi("DHT_PASSIVE_PORT", "6881"); err != nil {
		return nil, err
	}
	if c.DHTPassivePeerTTL, err = dur("DHT_PASSIVE_PEER_TTL", "30m"); err != nil {
		return nil, err
	}
	if c.DHTPassiveJanitorInterval, err = dur("DHT_PASSIVE_JANITOR_INTERVAL", "1h"); err != nil {
		return nil, err
	}
	if c.DHTPassiveMaxPerHash, err = atoi("DHT_PASSIVE_MAX_PER_HASH", "500"); err != nil {
		return nil, err
	}

	if c.APIToken == "" {
		return nil, fmt.Errorf("API_TOKEN env var is required (generate with: openssl rand -hex 32)")
	}

	return c, nil
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func atoi(key, def string) (int, error) {
	v := getenv(key, def)
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func dur(key, def string) (time.Duration, error) {
	v := getenv(key, def)
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}
