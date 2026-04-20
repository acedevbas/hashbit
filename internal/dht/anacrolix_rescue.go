package dht

// Rescue lookup implementation using anacrolix/dht/v2. This is the battle-
// tested upstream library — we use it ONLY as a fallback for hashes our
// hand-rolled iterative lookup couldn't find (small-swarm / edge-case
// hashes whose peer records live on k-bucket regions our walk bails out
// of early). The main hot path stays on our custom Client because its
// batch throughput is higher and it already returns data for the 80 %
// majority of popular hashes; anacrolix is slower but deeper.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	adht "github.com/anacrolix/dht/v2"
	aplog "github.com/anacrolix/log"
)

// RescueClient wraps an anacrolix/dht/v2 Server for occasional deep
// lookups. The Server maintains its own persistent routing table and
// re-uses it across rescue calls, so after a warm-up the walks are
// far cheaper than full bootstrap-from-scratch traversals.
type RescueClient struct {
	srv  *adht.Server
	conn net.PacketConn

	bootOnce sync.Once
}

// NewRescueClient binds its own UDP port and starts anacrolix's background
// table maintainer. Kicks off bootstrap in the background so the first
// Lookup doesn't block waiting for it.
func NewRescueClient() (*RescueClient, error) {
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("udp listen: %w", err)
	}
	cfg := adht.NewDefaultServerConfig()
	cfg.Conn = conn
	cfg.Logger = aplog.NewLogger().WithFilterLevel(aplog.Critical)
	srv, err := adht.NewServer(cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dht server: %w", err)
	}
	go func() { _, _ = srv.Bootstrap() }()
	go srv.TableMaintainer()
	return &RescueClient{srv: srv, conn: conn}, nil
}

// Close tears down the rescue client's socket and background goroutines.
func (rc *RescueClient) Close() error {
	rc.srv.Close()
	return rc.conn.Close()
}

// Lookup does an anacrolix AnnounceTraversal with BEP 33 scrape enabled,
// drains the peers channel until either deadline or channel close, and
// returns the aggregated result. Unlike the hand-rolled Client.Lookup this
// one reliably walks deep because the library handles k-bucket expansion
// and rate-limit coordination across every node it visits.
func (rc *RescueClient) Lookup(ctx context.Context, infohash [IDLen]byte, timeout time.Duration) (*Result, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	start := time.Now()
	ann, err := rc.srv.AnnounceTraversal(infohash, adht.Scrape())
	if err != nil {
		return nil, fmt.Errorf("announce traversal: %w", err)
	}
	defer ann.Close()

	// Separate deadline for the traversal itself. When it fires we stop
	// visiting new nodes, then drain buffered channel sends for a short
	// window so in-flight replies aren't thrown away before they reach us.
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	peers := make(map[string]struct{})
	var mergedSeeds, mergedPeersBF [256]byte
	bep33 := 0

	absorb := func(pv adht.PeersValues) {
		for _, p := range pv.Peers {
			if p.Port == 0 || !usableIP(p.IP) {
				continue
			}
			peers[fmt.Sprintf("%s:%d", p.IP, p.Port)] = struct{}{}
		}
		if pv.Return.BFsd != nil {
			bep33++
			for i, b := range pv.Return.BFsd {
				mergedSeeds[i] |= b
			}
		}
		if pv.Return.BFpe != nil {
			for i, b := range pv.Return.BFpe {
				mergedPeersBF[i] |= b
			}
		}
	}

	// Main loop.
collect:
	for {
		select {
		case pv, ok := <-ann.Peers:
			if !ok {
				break collect
			}
			absorb(pv)
		case <-lookupCtx.Done():
			ann.StopTraversing()
			// Short drain window: we've signalled stop, now give
			// in-flight responses ~3s to land. Beyond that the extra
			// wait dominates tick time on batches with many empty hashes.
			drainCtx, drainCancel := context.WithTimeout(context.Background(), 3*time.Second)
			for {
				select {
				case pv, ok := <-ann.Peers:
					if !ok {
						drainCancel()
						break collect
					}
					absorb(pv)
				case <-drainCtx.Done():
					drainCancel()
					break collect
				}
			}
		}
	}

	res := &Result{
		Peers:           make([]string, 0, len(peers)),
		Elapsed:         time.Since(start),
		BEP33Responders: bep33,
		MergedBFSeeds:   mergedSeeds,
		MergedBFPeers:   mergedPeersBF,
	}
	for p := range peers {
		res.Peers = append(res.Peers, p)
	}
	if bep33 > 0 {
		res.EstSeeds = estimateSwarmSize(mergedSeeds)
		res.EstPeers = estimateSwarmSize(mergedPeersBF)
	}
	return res, nil
}
