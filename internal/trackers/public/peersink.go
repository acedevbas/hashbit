package public

// PeerSink is a write-only interface for persisting peer endpoints we
// observe in tracker announce replies. Implemented by the passive DHT peer
// cache so that `Record(infohash, peer)` appends the observation to the
// in-process write-behind batcher (non-blocking; dropped on buffer full).
//
// Scoped here rather than importing dht.PassivePeerCache to avoid a
// dependency cycle — public is a peer *producer*, dht is the
// infrastructure host. The signature matches PassivePeerCache.Record
// one-for-one so main.go can inject it directly.
type PeerSink interface {
	Record(infohash, peer string)
}
