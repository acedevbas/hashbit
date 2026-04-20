//go:build !cgo
// +build !cgo

// TCP-only dialer for pure-Go builds (CGO_ENABLED=0).
//
// Production Docker image is built without cgo to keep the runtime small —
// no libstdc++, no libcrypto, no C runtime dependency on Alpine. That means
// μTP via anacrolix/go-libutp is unavailable there. This stub keeps the
// btprobe API surface identical (TransportMode, CloseUTP, dialRace) so
// callers compile without conditionals, but all μTP paths become no-ops.
//
// Operational impact: we probe only TCP peers. On healthy swarms TCP reaches
// roughly 70 % of seeders (seedboxes, VPS, well-connected home clients); the
// remaining ~30 % are residential NAT clients whose inbound TCP is blocked
// but whose DHT UDP port is open, and those we miss here. BEP 33 estimates
// and the raw peer list remain intact regardless.
package btprobe

import (
	"context"
	"net"
	"time"
)

// TransportMode mirrors the cgo file's enum so client code compiles under
// both build tags. Under no-cgo it's effectively advisory — every Mode
// value collapses to TCP-only behaviour.
type TransportMode int

const (
	ModeRace TransportMode = iota
	ModeTCPOnly
	ModeUTPOnly
)

var Mode TransportMode = ModeTCPOnly

// CloseUTP is a no-op in no-cgo builds. Exposed so callers that defer it
// at process exit compile unconditionally.
func CloseUTP() {}

// dialRace opens a TCP connection to addr with the given timeout. The
// returned proto is always "tcp" — callers that branch on proto will
// see no μTP results under this build tag.
func dialRace(ctx context.Context, addr string, timeout time.Duration) (net.Conn, string, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := net.Dialer{}
	c, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, "", err
	}
	return c, "tcp", nil
}
