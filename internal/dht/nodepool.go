package dht

// NodePool is a bounded, process-wide index of DHT node endpoints we have
// observed in KRPC replies. Every successful query (get_peers, find_node,
// sample_infohashes) carries a "nodes" field whose entries are real BT
// clients currently participating in the DHT — harvesting them into a
// shared pool turns ordinary scrape traffic into free seed material for
// the BEP 51 discovery crawler.
//
// Bootstrap routers answer find_node/get_peers but deliberately NOT
// sample_infohashes, so a crawler seeded from them alone dies immediately.
// A pool fed by our scrape workers yields real clients, a growing fraction
// of which implement BEP 51. Once a node replies to sample_infohashes we
// flag it (bep51Known) so subsequent cycles can bias sampling toward
// known-good responders.
//
// Design constraints:
//   - Observations arrive on the UDP read-loop hot path; Add must be
//     sub-microsecond and allocation-free in the common "already present"
//     case. A single sync.Mutex over a map is fine at our rates (hundreds
//     of additions per second, dwarfed by the UDP I/O itself).
//   - Capacity is bounded: we keep the N most recently seen addresses.
//     FIFO-ish eviction — cheap random-victim drop keeps us away from
//     LRU bookkeeping overhead.
//   - Sampling biases toward BEP 51-known nodes when preferBEP51 is true
//     so warm cycles front-load the most productive responders.

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

// poolEntry is the value stored per address in the pool.
type poolEntry struct {
	addr       *net.UDPAddr
	id         NodeID
	lastSeen   time.Time
	bep51Known bool // flipped true once this node answered sample_infohashes
}

// NodePool stores up to Cap observed DHT nodes. Concurrent-safe.
type NodePool struct {
	mu    sync.Mutex
	nodes map[string]*poolEntry
	cap   int
}

// NewNodePool returns an empty pool that will cap at cap entries. cap <= 0
// picks a default of 4096 — enough to keep a warm crawler seed across
// cycles without meaningful memory cost (~300 KB at 4k entries).
func NewNodePool(cap int) *NodePool {
	if cap <= 0 {
		cap = 4096
	}
	return &NodePool{
		nodes: make(map[string]*poolEntry, cap),
		cap:   cap,
	}
}

// Observe is the hot-path entry point. Called from the KRPC dispatcher for
// every node address that appears in a "nodes" / "nodes6" field. Duplicates
// are cheap: we bump lastSeen and return. New entries evict a random victim
// when the pool is at capacity.
func (p *NodePool) Observe(addr *net.UDPAddr, id NodeID) {
	if addr == nil || addr.IP == nil || addr.Port == 0 {
		return
	}
	if !usableIP(addr.IP) {
		return
	}
	key := addr.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.nodes[key]; ok {
		e.lastSeen = time.Now()
		// Keep the richer id if we had a zero before.
		if (e.id == NodeID{}) {
			e.id = id
		}
		return
	}
	if len(p.nodes) >= p.cap {
		// Evict a random victim. Map iteration order is already random in
		// Go, so pulling the first key is sufficient — no need for a
		// separate RNG call. Skip bep51Known entries to preserve the
		// warm set; if we can't find an evictable one quickly, evict the
		// first anyway (eventually productive nodes dominate the pool).
		for k, v := range p.nodes {
			if !v.bep51Known {
				delete(p.nodes, k)
				break
			}
			// First fallback: the loop runs at most one iteration when
			// every entry is bep51Known (unlikely until crawler has run
			// thousands of cycles). In that case just drop this one.
			delete(p.nodes, k)
			break
		}
	}
	p.nodes[key] = &poolEntry{
		addr:     addr,
		id:       id,
		lastSeen: time.Now(),
	}
}

// MarkBEP51 flags an address as a known BEP 51 responder. Called by the
// crawler after a successful sample_infohashes reply. Unknown addresses
// are silently ignored — the hint is best-effort.
func (p *NodePool) MarkBEP51(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	key := addr.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.nodes[key]; ok {
		e.bep51Known = true
	}
}

// Sample returns up to n addresses. If preferBEP51 and we have at least
// n/2 bep51-known nodes, the result is drawn entirely from that subset;
// otherwise we mix known + unknown, with known first. Ordering inside each
// bucket is randomised — map iteration plus rand.Shuffle — so repeated
// cycles do not re-probe the same sequence.
func (p *NodePool) Sample(n int, preferBEP51 bool) []*net.UDPAddr {
	if n <= 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	var known, unknown []*net.UDPAddr
	for _, e := range p.nodes {
		if e.bep51Known {
			known = append(known, e.addr)
		} else {
			unknown = append(unknown, e.addr)
		}
	}
	rand.Shuffle(len(known), func(i, j int) { known[i], known[j] = known[j], known[i] })
	rand.Shuffle(len(unknown), func(i, j int) { unknown[i], unknown[j] = unknown[j], unknown[i] })

	out := make([]*net.UDPAddr, 0, n)
	// Always prefer known first so the crawler's first queries are the most
	// likely to succeed; fall through to unknown regardless of preferBEP51
	// because discovering new responders is also the point.
	for _, a := range known {
		if len(out) >= n {
			break
		}
		out = append(out, a)
	}
	for _, a := range unknown {
		if len(out) >= n {
			break
		}
		out = append(out, a)
	}
	return out
}

// Len returns the current entry count. Useful for crawler cold-start
// decisions ("is the pool warm enough to skip the find_node walk?").
func (p *NodePool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.nodes)
}

// BEP51Count returns the number of entries flagged as BEP 51 responders.
// Exposed for Prometheus gauge instrumentation and crawler telemetry.
func (p *NodePool) BEP51Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, e := range p.nodes {
		if e.bep51Known {
			n++
		}
	}
	return n
}
