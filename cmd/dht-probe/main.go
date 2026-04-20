// dht-probe performs a DHT get_peers lookup and, optionally, a BitTorrent
// handshake against each returned peer to distinguish seeds from leechers.
// When PEX is enabled each responding peer is also asked (via BEP 10 + BEP 11)
// for its contact list, and those new addresses are handshake-probed in a
// second pass. No database is touched — this is a diagnostic harness.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/acedevbas/hashbit/internal/btprobe"
	"github.com/acedevbas/hashbit/internal/dht"
)

func main() {
	timeout := flag.Duration("timeout", 15*time.Second, "overall DHT lookup timeout")
	qTimeout := flag.Duration("query-timeout", 2*time.Second, "per-query read timeout")
	alpha := flag.Int("alpha", 8, "DHT parallelism factor")
	noScrape := flag.Bool("no-scrape", false, "disable BEP 33 scrape=1 flag (use when needing raw peer list)")
	fingerprint := flag.Bool("fingerprint", true, "BT handshake to classify seeds/leechers")
	fpConc := flag.Int("fp-conc", 100, "max concurrent TCP fingerprint sockets")
	fpTimeout := flag.Duration("fp-timeout", 5*time.Second, "per-peer handshake + PEX-wait timeout")
	pex := flag.Bool("pex", true, "harvest additional peers via PEX and probe them")
	pexPasses := flag.Int("pex-passes", 1, "how many PEX expansion rounds to run")
	proto := flag.String("proto", "race", "transport: race | tcp | utp")
	printN := flag.Int("print", 20, "max peers to print")
	flag.Parse()

	switch *proto {
	case "race":
		btprobe.Mode = btprobe.ModeRace
	case "tcp":
		btprobe.Mode = btprobe.ModeTCPOnly
	case "utp":
		btprobe.Mode = btprobe.ModeUTPOnly
	default:
		fmt.Fprintf(os.Stderr, "unknown -proto=%s\n", *proto)
		os.Exit(2)
	}
	defer btprobe.CloseUTP()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: dht-probe [flags] <40-hex-infohash>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	hexHash := flag.Arg(0)
	if len(hexHash) != 40 {
		fmt.Fprintln(os.Stderr, "infohash must be exactly 40 hex characters")
		os.Exit(2)
	}
	b, err := hex.DecodeString(hexHash)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad hex:", err)
		os.Exit(2)
	}
	var ih [20]byte
	copy(ih[:], b)

	// --- Phase 1: DHT lookup ---
	res, err := dht.Lookup(context.Background(), ih, dht.Options{
		Timeout:      *timeout,
		QueryTimeout: *qTimeout,
		Alpha:        *alpha,
		NoScrape:     *noScrape,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "dht error:", err)
		os.Exit(1)
	}
	fmt.Println("=== DHT get_peers (with BEP 33 scrape=1) ===")
	fmt.Printf("infohash:        %s\n", hexHash)
	fmt.Printf("elapsed:         %s\n", res.Elapsed.Round(time.Millisecond))
	fmt.Printf("rounds:          %d\n", res.Rounds)
	fmt.Printf("nodes queried:   %d\n", res.NodesQueried)
	fmt.Printf("nodes seen:      %d\n", res.NodesSeen)
	fmt.Printf("unique peers:    %d  (raw get_peers values)\n", len(res.Peers))
	if res.BEP33Responders > 0 {
		fmt.Println()
		fmt.Println("--- BEP 33 bloom-filter scrape ---")
		fmt.Printf("bep33 responders:%d / %d nodes\n", res.BEP33Responders, res.NodesQueried)
		fmt.Printf("est. seeders:    %d\n", res.EstSeeds)
		fmt.Printf("est. leechers:   %d\n", res.EstPeers)
	} else {
		fmt.Println("--- BEP 33: no bloom-filter responses collected ---")
	}

	if !*fingerprint || len(res.Peers) == 0 {
		printPeers(res.Peers, *printN)
		return
	}

	// --- Phase 2: fingerprint initial DHT peers ---
	allSeen := make(map[string]struct{}, len(res.Peers))
	for _, p := range res.Peers {
		allSeen[p] = struct{}{}
	}
	var allResults []btprobe.Result

	peersToProbe := res.Peers
	totalSeeds, totalLeechers, totalDead, totalUnknown := 0, 0, 0, 0
	totalProbed := 0
	var fpElapsed time.Duration

	for pass := 0; ; pass++ {
		label := "initial DHT peers"
		if pass > 0 {
			label = fmt.Sprintf("PEX-discovered peers (pass %d)", pass)
		}
		fmt.Println()
		fmt.Printf("=== BT handshake fingerprint \u2014 %s ===\n", label)
		fmt.Printf("probing %d peers (conc=%d, timeout=%s, pex=%v)...\n", len(peersToProbe), *fpConc, *fpTimeout, *pex)

		sum := btprobe.FingerprintPeers(context.Background(), ih, peersToProbe, *fpConc, *fpTimeout)
		fpElapsed += sum.Elapsed
		totalProbed += sum.Total
		totalSeeds += sum.Seeds
		totalLeechers += sum.Leechers
		totalDead += sum.Dead
		totalUnknown += sum.Unknown
		allResults = append(allResults, sum.Results...)

		fmt.Printf("elapsed:         %s\n", sum.Elapsed.Round(time.Millisecond))
		fmt.Printf("seeds:           %d\n", sum.Seeds)
		fmt.Printf("leechers:        %d\n", sum.Leechers)
		fmt.Printf("unknown:         %d\n", sum.Unknown)
		fmt.Printf("dead/unreach:    %d\n", sum.Dead)
		fmt.Printf("via tcp:         %d\n", sum.ByTCP)
		fmt.Printf("via \u03bctp:         %d\n", sum.ByUTP)
		alive := sum.Seeds + sum.Leechers
		if alive > 0 {
			fmt.Printf("alive/responded: %d  (seed ratio %.1f%%)\n", alive, 100*float64(sum.Seeds)/float64(alive))
		}
		if *pex {
			fmt.Printf("new PEX peers:   %d\n", len(sum.NewPeers))
		}

		if !*pex || pass+1 >= *pexPasses {
			break
		}
		// Deduplicate discovered PEX peers against everything seen so far.
		next := make([]string, 0, len(sum.NewPeers))
		for _, p := range sum.NewPeers {
			if _, had := allSeen[p]; had {
				continue
			}
			allSeen[p] = struct{}{}
			next = append(next, p)
		}
		if len(next) == 0 {
			break
		}
		peersToProbe = next
	}

	fmt.Println()
	fmt.Println("=== TOTAL ===")
	fmt.Printf("DHT peers:         %d\n", len(res.Peers))
	fmt.Printf("Peers probed:      %d  (DHT + PEX discovered)\n", totalProbed)
	fmt.Printf("Confirmed seeds:   %d\n", totalSeeds)
	fmt.Printf("Confirmed leech:   %d\n", totalLeechers)
	fmt.Printf("Unknown:           %d\n", totalUnknown)
	fmt.Printf("Dead/unreach:      %d\n", totalDead)
	fmt.Printf("Fingerprint time:  %s\n", fpElapsed.Round(time.Millisecond))

	printPeersByStatus(allResults, *printN)
}

func printPeers(peers []string, limit int) {
	if limit == 0 || len(peers) == 0 {
		return
	}
	fmt.Println()
	if limit > len(peers) {
		limit = len(peers)
	}
	for _, p := range peers[:limit] {
		fmt.Println(" ", p)
	}
	if len(peers) > limit {
		fmt.Printf("  ... (+%d more)\n", len(peers)-limit)
	}
}

func printPeersByStatus(results []btprobe.Result, limit int) {
	if limit == 0 {
		return
	}
	fmt.Println()
	shown := 0
	for _, r := range results {
		if r.Status != btprobe.StatusSeed {
			continue
		}
		if shown >= limit {
			break
		}
		fmt.Printf("  [seed]     %s\n", r.Addr)
		shown++
	}
	for _, r := range results {
		if r.Status != btprobe.StatusLeecher {
			continue
		}
		if shown >= limit {
			break
		}
		fmt.Printf("  [leecher]  %s\n", r.Addr)
		shown++
	}
}
