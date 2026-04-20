// Package webtorrent scrapes WebTorrent WebSocket trackers — the swarm of
// browser-based BitTorrent peers that talk WebRTC after discovering each other
// through a JSON-over-WS signalling protocol. Their infohash space overlaps
// with classic BT, but the peer population is disjoint: browsers never appear
// on TCP/UDP trackers, and desktop clients rarely announce to WSS trackers.
// Scraping them therefore uncovers swarm health that the other six scrapers
// are structurally blind to.
package webtorrent

// Endpoints is a curated list of live WSS/WS tracker URLs as of 2025.
// Paths like /announce are kept as-is; the dialer strips them because the
// WebTorrent protocol is path-agnostic and some servers 404 on the path.
var Endpoints = []string{
	"wss://tracker.webtorrent.dev",
	"wss://tracker.openwebtorrent.com",
	"wss://tracker.btorrent.xyz",
	"wss://tracker.files.fm:7073/announce",
	"ws://tracker.files.fm:7072/announce",
	"wss://tracker.ghostchu-services.top:443/announce",
}
