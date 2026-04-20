// Package trackers defines tracker IDs and shared types.
package trackers

// Canonical tracker IDs used across the service.
const (
	Rutor      = "rutor"
	NNMClub    = "nnm-club"
	Kinozal    = "kinozal"
	Rutracker  = "rutracker"
	Public     = "public"     // aggregated scrape across many HTTP+UDP public trackers
	DHT        = "dht"        // Mainline DHT get_peers + BEP 33 bloom-filter scrape
	WebTorrent = "webtorrent" // WSS trackers serving the WebRTC/browser BT swarm
)

// All known tracker IDs (order matters for display).
var All = []string{Rutor, NNMClub, Kinozal, Rutracker, Public, DHT, WebTorrent}

// ScrapeResult is a per-hash result from a single tracker query.
// Some trackers (rutracker) can only report peer count, not seed/leech split;
// in that case Seeders/Leechers are -1 and PeerCount is set.
type ScrapeResult struct {
	Seeders   int32 // -1 means "unknown/not provided by this tracker"
	Leechers  int32 // -1 means unknown
	Completed int32 // -1 means unknown
	PeerCount int32 // -1 means unknown; used by rutracker
}

// Status flags the interpretation of a tracker response.
type Status int

const (
	StatusOK       Status = iota // got data (seeders, peers, or both)
	StatusNotFound               // tracker does not know this hash
	StatusError                  // network or protocol error
)

// Response wraps a single-hash result with its interpretation.
type Response struct {
	Status Status
	Result ScrapeResult
	Err    string
}

// Unknown returns a sentinel ScrapeResult for missing data.
func Unknown() ScrapeResult {
	return ScrapeResult{Seeders: -1, Leechers: -1, Completed: -1, PeerCount: -1}
}
