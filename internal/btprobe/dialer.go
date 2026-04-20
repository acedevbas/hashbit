//go:build cgo
// +build cgo

// TCP / μTP racing dialer.
//
// Modern BitTorrent clients — notably qBittorrent, μTorrent and Transmission —
// default to μTP (BEP 29) for outbound connections because it NAT-traverses
// better than TCP through typical home routers. Probing peers over TCP only
// therefore misses roughly half of the real swarm. We race both transports
// per peer: TCP usually wins on seedboxes and well-connected clients; μTP
// wins on residential peers whose NAT blocks inbound TCP SYN but keeps their
// UDP DHT-port open.
//
// libutp (anacrolix/go-libutp) is a cgo wrapper around the reference C
// implementation. We share a single process-wide utp.Socket so all probes
// multiplex onto the same UDP port — libutp handles per-conversation
// connection IDs internally.
package btprobe

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	utp "github.com/anacrolix/go-libutp"
)

// TransportMode controls how dialRace picks transports.
// ModeRace tries TCP and μTP in parallel, first success wins.
// ModeTCPOnly disables μTP entirely (matches behavior pre-libutp).
// ModeUTPOnly skips TCP — useful for validating that libutp alone works.
type TransportMode int

const (
	ModeRace TransportMode = iota
	ModeTCPOnly
	ModeUTPOnly
)

// Mode is the current per-process transport policy.
var Mode TransportMode = ModeRace

var (
	utpSockOnce sync.Once
	utpSock     *utp.Socket
	utpSockErr  error
)

func getUTPSocket() (*utp.Socket, error) {
	utpSockOnce.Do(func() {
		utpSock, utpSockErr = utp.NewSocket("udp", ":0")
	})
	return utpSock, utpSockErr
}

// CloseUTP releases the shared μTP socket. Safe to call at process exit.
func CloseUTP() {
	if utpSock != nil {
		_ = utpSock.Close()
	}
}

type dialOutcome struct {
	conn  net.Conn
	proto string
	err   error
}

// dialRace dials TCP and μTP according to the active TransportMode and
// returns the first successful connection. Loser goroutine is drained async.
func dialRace(ctx context.Context, addr string, timeout time.Duration) (net.Conn, string, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)

	switch Mode {
	case ModeTCPOnly:
		defer cancel()
		d := net.Dialer{}
		c, err := d.DialContext(dctx, "tcp", addr)
		if err != nil {
			return nil, "", err
		}
		return c, "tcp", nil
	case ModeUTPOnly:
		defer cancel()
		s, err := getUTPSocket()
		if err != nil {
			return nil, "", err
		}
		c, err := s.DialContext(dctx, "udp", addr)
		if err != nil {
			return nil, "", err
		}
		return c, "utp", nil
	}

	ch := make(chan dialOutcome, 2)
	go func() {
		d := net.Dialer{}
		c, err := d.DialContext(dctx, "tcp", addr)
		ch <- dialOutcome{c, "tcp", err}
	}()
	go func() {
		s, err := getUTPSocket()
		if err != nil {
			ch <- dialOutcome{nil, "utp", err}
			return
		}
		c, err := s.DialContext(dctx, "udp", addr)
		ch <- dialOutcome{c, "utp", err}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil && r.conn != nil {
			go func() {
				cancel()
				r2 := <-ch
				if r2.conn != nil {
					_ = r2.conn.Close()
				}
			}()
			return r.conn, r.proto, nil
		}
		if firstErr == nil {
			firstErr = r.err
		}
	}
	cancel()
	if firstErr == nil {
		firstErr = errors.New("both tcp and utp dial failed")
	}
	return nil, "", firstErr
}
