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
	RutorBatchSize     int
	NNMBatchSize       int
	KinozalRateLimit   int // req/sec
	RutrackerRateLimit int // req/sec

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
	if c.KinozalRateLimit, err = atoi("KINOZAL_RPS", "5"); err != nil {
		return nil, err
	}
	if c.RutrackerRateLimit, err = atoi("RUTRACKER_RPS", "5"); err != nil {
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
