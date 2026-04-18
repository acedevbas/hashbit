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
	"github.com/acedevbas/hashbit/internal/httpclient"
	"github.com/acedevbas/hashbit/internal/scheduler"
	"github.com/acedevbas/hashbit/internal/trackers"
	"github.com/acedevbas/hashbit/internal/trackers/kinozal"
	"github.com/acedevbas/hashbit/internal/trackers/nnmclub"
	"github.com/acedevbas/hashbit/internal/trackers/rutor"
	"github.com/acedevbas/hashbit/internal/trackers/rutracker"
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
	var kinozalSc *kinozal.Scraper
	if cfg.KinozalUK != "" {
		kinozalSc = kinozal.New(hc, cfg.KinozalUK)
	}

	// Register for force-scrape (used by API).
	apiScrapers := map[string]scheduler.Scraper{
		trackers.Rutor:     rutorSc,
		trackers.NNMClub:   nnmSc,
		trackers.Rutracker: rutSc,
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

	// Start HTTP API.
	srv := &api.Server{
		Pool:            pool,
		Log:             log,
		APIToken:        cfg.APIToken,
		Scrapers:        apiScrapers,
		OnDemandTimeout: cfg.OnDemandTimeout,
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
