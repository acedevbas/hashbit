package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acedevbas/hashbit/internal/api"
	"github.com/acedevbas/hashbit/internal/config"
	"github.com/acedevbas/hashbit/internal/db"
	"github.com/acedevbas/hashbit/internal/dht"
	"github.com/acedevbas/hashbit/internal/httpclient"
	"github.com/acedevbas/hashbit/internal/metrics"
	"github.com/acedevbas/hashbit/internal/scheduler"
	"github.com/acedevbas/hashbit/internal/trackers"
	"github.com/acedevbas/hashbit/internal/trackers/dhtscraper"
	"github.com/acedevbas/hashbit/internal/trackers/kinozal"
	"github.com/acedevbas/hashbit/internal/trackers/nnmclub"
	"github.com/acedevbas/hashbit/internal/trackers/public"
	"github.com/acedevbas/hashbit/internal/trackers/rutor"
	"github.com/acedevbas/hashbit/internal/trackers/rutracker"
	"github.com/acedevbas/hashbit/internal/trackers/webtorrent"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	if cfg.KinozalUK == "" {
		log.Warn("KINOZAL_UK not set — kinozal worker will be disabled")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pool, err := db.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("db", "err", err)
		os.Exit(1)
	}
	defer pool.Close()
	log.Info("database ready")

	hc := httpclient.New(cfg.UserAgent, cfg.TrackerTimeout)

	// Build scrapers.
	rutorSc := rutor.New(hc)
	nnmSc := nnmclub.New(hc)
	rutSc := rutracker.New(hc)
	publicSc := public.New(hc, cfg.PublicConcurrency, cfg.PublicAnnounce,
		cfg.PublicRefreshInterval, cfg.PublicRefreshHTTPURL, cfg.PublicRefreshUDPURL)
	defer func() { _ = publicSc.Close() }()
	dhtSc, err := dhtscraper.New(cfg.DHTClients, cfg.DHTClients6, cfg.DHTConcurrency, cfg.DHTLookupTimeout, cfg.DHTAlpha)
	if err != nil {
		log.Error("dht", "err", err)
		os.Exit(1)
	}
	defer dhtSc.Close()
	webtorrentSc := webtorrent.New(cfg.WebTorrentConcurrency)
	var kinozalSc *kinozal.Scraper
	if cfg.KinozalUK != "" {
		kinozalSc = kinozal.New(hc, cfg.KinozalUK)
	}

	// Passive DHT node ("Sybil-lite"): listens on a stable UDP port, responds
	// to incoming KRPC queries, and harvests every observed announce_peer into
	// the passive-peer cache. Anything that routes a get_peers/announce_peer
	// through us — i.e. any peer whose Kademlia path crosses our node id — is
	// a free peer observation. The passive cache also feeds the active DHT
	// scraper so cache hits skip the network round-trip.
	var passiveNode *dht.PassiveNode
	var passiveCache *dht.PassivePeerCache
	if cfg.DHTPassiveEnabled {
		passiveCache = dht.NewPassivePeerCache(pool, cfg.DHTPassiveMaxPerHash)
		passiveCache.Start(ctx)
		go passiveCache.RunJanitor(ctx, 2*cfg.DHTPassivePeerTTL, cfg.DHTPassiveJanitorInterval)

		passiveNode, err = dht.NewPassiveNode(dht.PassiveOptions{
			Port:     cfg.DHTPassivePort,
			Recorder: passiveCache,
		})
		if err != nil {
			log.Error("dht passive node", "err", err, "port", cfg.DHTPassivePort)
			// non-fatal: the active DHT scraper still works without the passive observer
		} else {
			passiveNode.Start(ctx)
			defer func() { _ = passiveNode.Close() }()
			log.Info("dht passive node listening", "port", cfg.DHTPassivePort)
		}
		defer passiveCache.Close()

		// Wire the cache into the active DHT scraper so fresh observed peers
		// supplement each lookup without waiting on a live round-trip.
		dhtSc.SetPassiveCache(passiveCache, cfg.DHTPassivePeerTTL, 200)
	}

	// Register for force-scrape (used by API).
	apiScrapers := map[string]scheduler.Scraper{
		trackers.Rutor:      rutorSc,
		trackers.NNMClub:    nnmSc,
		trackers.Rutracker:  rutSc,
		trackers.Public:     publicSc,
		trackers.DHT:        dhtSc,
		trackers.WebTorrent: webtorrentSc,
	}
	if kinozalSc != nil {
		apiScrapers[trackers.Kinozal] = kinozalSc
	}

	// Start workers.
	workers := []*scheduler.Worker{
		scheduler.ConfigureWorker(trackers.Rutor, rutorSc, cfg, pool, log,
			cfg.RutorBatchSize, cfg.ScrapeTick, 0),
		scheduler.ConfigureWorker(trackers.NNMClub, nnmSc, cfg, pool, log,
			cfg.NNMBatchSize, cfg.ScrapeTick, 0),
		scheduler.ConfigureWorker(trackers.Rutracker, rutSc, cfg, pool, log,
			1, cfg.AnnounceTick, cfg.RutrackerRateLimit),
		scheduler.ConfigureWorker(trackers.Public, publicSc, cfg, pool, log,
			cfg.PublicBatchSize, cfg.ScrapeTick, 0),
		scheduler.ConfigureWorker(trackers.DHT, dhtSc, cfg, pool, log,
			cfg.DHTBatchSize, cfg.ScrapeTick, 0),
		scheduler.ConfigureWorker(trackers.WebTorrent, webtorrentSc, cfg, pool, log,
			cfg.WebTorrentBatchSize, cfg.ScrapeTick, 0),
	}
	if kinozalSc != nil {
		workers = append(workers,
			scheduler.ConfigureWorker(trackers.Kinozal, kinozalSc, cfg, pool, log,
				1, cfg.AnnounceTick, cfg.KinozalRateLimit),
		)
	}
	for _, w := range workers {
		go w.Run(ctx)
	}

	// Background sampler that refreshes DB-backed Prometheus gauges every 30s.
	// Running this before the HTTP server starts means /metrics already has
	// non-zero gauges by the time the first scrape hits us.
	metrics.StartGaugeSampler(ctx, pool, log, 30*time.Second)

	// BEP 51 sample_infohashes crawler. Opens its own Client (separate UDP
	// socket) so discovery traffic does not starve the scrape pool.
	// Discovered hashes land in the `discovered_hashes` table — the operator
	// promotes them into `infohashes` on their own schedule.
	//
	// NodePool is shared across every DHT client in the process: each
	// client's KRPC dispatcher calls pool.Observe on every "nodes" entry
	// it sees, which gives the crawler a warm seed of real BT clients
	// harvested from ongoing scrape traffic. Without this the crawler
	// would be stuck seeding from Mainline DHT bootstrap routers, which
	// deliberately do not implement sample_infohashes.
	var bep51Client *dht.Client
	if cfg.DHTBEP51Enabled {
		nodePool := dht.NewNodePool(4096)
		dhtSc.SetNodeObserver(nodePool.Observe)

		c, err := dht.NewClient()
		if err != nil {
			log.Error("bep51 client", "err", err)
		} else {
			bep51Client = c
			bep51Client.SetNodeObserver(nodePool.Observe)
			defer func() { _ = bep51Client.Close() }()
			crawler := dht.NewBEP51Crawler(bep51Client, nodePool, pool, log, dht.BEP51CrawlerOptions{
				Interval:     cfg.DHTBEP51Interval,
				MaxNodes:     cfg.DHTBEP51MaxNodes,
				Alpha:        cfg.DHTBEP51Alpha,
				QueryTimeout: cfg.DHTBEP51QueryTimeout,
			})
			go crawler.Run(ctx)
		}
	}

	// Start HTTP API.
	srv := &api.Server{
		Pool:            pool,
		Log:             log,
		APIToken:        cfg.APIToken,
		Scrapers:        apiScrapers,
		OnDemandTimeout: cfg.OnDemandTimeout,
		Peers:           dhtSc,
	}
	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Info("http listening", "addr", cfg.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http", "err", err)
			cancel()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, c2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer c2()
	_ = httpSrv.Shutdown(shutdownCtx)
}
