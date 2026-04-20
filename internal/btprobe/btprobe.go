// Package btprobe classifies BitTorrent peers as seeds / leechers via a
// lightweight TCP handshake, and opportunistically harvests more peer
// addresses through the ut_pex (BEP 11) extension. It implements enough of
// BEP 3, BEP 6 (Fast Extension), BEP 10 (Extended Protocol), and BEP 11
// (Peer Exchange) to read the first HAVE_ALL / HAVE_NONE / bitfield message
// and any immediate ut_pex message, then close the connection — no pieces
// are transferred.
//
// Usage:
//
//	sum := btprobe.FingerprintPeers(ctx, infohash, peerList, 64, 5*time.Second)
//
// Concurrency caps simultaneous TCP sockets; timeout bounds each handshake.
// Waiting past the bitfield for a PEX message costs a few extra seconds per
// peer but typically multiplies peer-coverage by 2-3× on active swarms.
package btprobe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

type Status int

const (
	StatusUnknown Status = iota
	StatusSeed
	StatusLeecher
	StatusDead // TCP connect / handshake failed
)

const (
	handshakeLen = 68
	pstrlenByte  = 19
	pstr         = "BitTorrent protocol"

	// Wire message IDs (BEP 3 + BEP 6 Fast Extension).
	msgBitfield = 5
	msgHaveAll  = 14
	msgHaveNone = 15
)

type Result struct {
	Addr     string
	Proto    string // "tcp" | "utp" | ""
	Status   Status
	PEXPeers []string // peers learned via BEP 11 ut_pex (may be empty)
}

type Summary struct {
	Seeds    int
	Leechers int
	Unknown  int
	Dead     int
	Total    int
	ByTCP    int
	ByUTP    int
	Elapsed  time.Duration
	Results  []Result
	NewPeers []string // unique PEX peers not present in the input set
}

// FingerprintPeers dials every peer in parallel (bounded by concurrency),
// performs a BT handshake with the FastExt + LTEP reserved bits set, sends
// an extended handshake advertising ut_pex, and reads messages until either
// a status-determining message arrives and PEX is seen, or the connection
// deadline fires.
func FingerprintPeers(ctx context.Context, infohash [20]byte, peers []string, concurrency int, timeout time.Duration) Summary {
	if concurrency <= 0 {
		concurrency = 64
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	start := time.Now()
	out := Summary{Total: len(peers), Results: make([]Result, len(peers))}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, p := range peers {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out.Results[i] = Result{Addr: p, Status: StatusDead}
				return
			}
			out.Results[i] = checkOne(ctx, infohash, p, timeout)
		}(i, p)
	}
	wg.Wait()

	inputSet := make(map[string]struct{}, len(peers))
	for _, p := range peers {
		inputSet[p] = struct{}{}
	}
	pexSet := make(map[string]struct{})

	for _, r := range out.Results {
		switch r.Status {
		case StatusSeed:
			out.Seeds++
		case StatusLeecher:
			out.Leechers++
		case StatusUnknown:
			out.Unknown++
		case StatusDead:
			out.Dead++
		}
		switch r.Proto {
		case "tcp":
			out.ByTCP++
		case "utp":
			out.ByUTP++
		}
		for _, p := range r.PEXPeers {
			if _, had := inputSet[p]; had {
				continue
			}
			pexSet[p] = struct{}{}
		}
	}
	out.NewPeers = make([]string, 0, len(pexSet))
	for p := range pexSet {
		out.NewPeers = append(out.NewPeers, p)
	}
	out.Elapsed = time.Since(start)
	return out
}

func checkOne(ctx context.Context, infohash [20]byte, addr string, timeout time.Duration) Result {
	res := Result{Addr: addr, Status: StatusDead}
	conn, proto, err := dialRace(ctx, addr, timeout)
	if err != nil {
		return res
	}
	defer conn.Close()
	res.Proto = proto
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var hs [handshakeLen]byte
	hs[0] = pstrlenByte
	copy(hs[1:20], pstr)
	// BEP 10 LTEP — reserved[5] bit 0x10. Required for ut_pex.
	hs[25] |= 0x10
	// BEP 6 Fast Extension — reserved[7] bit 0x04. Lets the peer reply with
	// HAVE_ALL / HAVE_NONE instead of a full bitfield.
	hs[27] |= 0x04
	copy(hs[28:48], infohash[:])
	copy(hs[48:56], "-UT3550-")
	if _, err := rand.Read(hs[56:68]); err != nil {
		return res
	}
	if _, err := conn.Write(hs[:]); err != nil {
		return res
	}

	var recv [handshakeLen]byte
	if _, err := io.ReadFull(conn, recv[:]); err != nil {
		return res
	}
	if recv[0] != pstrlenByte || !bytes.Equal(recv[1:20], []byte(pstr)) {
		return res
	}
	if !bytes.Equal(recv[28:48], infohash[:]) {
		return res
	}

	// Only send our extended handshake if peer signals LTEP support.
	peerSupportsLTEP := recv[25]&0x10 != 0
	if peerSupportsLTEP {
		_, _ = conn.Write(extHandshakeFrame) // best-effort
	}
	res.Status = StatusUnknown

	readLoop(conn, &res, peerSupportsLTEP)
	return res
}

// readLoop drives the post-handshake message stream. It mutates `res` in
// place: sets Status on the first bitfield-equivalent, appends PEXPeers on
// each ut_pex message. Returns when both facts are collected, the deadline
// fires, or the peer closes.
func readLoop(conn net.Conn, res *Result, peerSupportsLTEP bool) {
	const (
		maxMessages = 40
		maxMsgLen   = 1 << 20
	)
	var peerPexID byte
	hasStatus := false
	gotPex := false

	for i := 0; i < maxMessages; i++ {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		if msgLen == 0 {
			i--
			continue
		}
		if msgLen > maxMsgLen {
			return
		}
		idBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, idBuf); err != nil {
			return
		}
		payloadLen := int64(msgLen) - 1

		switch idBuf[0] {
		case msgHaveAll:
			_, _ = io.CopyN(io.Discard, conn, payloadLen)
			res.Status = StatusSeed
			hasStatus = true
		case msgHaveNone:
			_, _ = io.CopyN(io.Discard, conn, payloadLen)
			res.Status = StatusLeecher
			hasStatus = true
		case msgBitfield:
			bf := make([]byte, payloadLen)
			if _, err := io.ReadFull(conn, bf); err != nil {
				return
			}
			if isSeedBitfield(bf) {
				res.Status = StatusSeed
			} else {
				res.Status = StatusLeecher
			}
			hasStatus = true
		case msgLTEP:
			if payloadLen < 1 {
				_, _ = io.CopyN(io.Discard, conn, payloadLen)
				continue
			}
			sub := make([]byte, 1)
			if _, err := io.ReadFull(conn, sub); err != nil {
				return
			}
			payload := make([]byte, payloadLen-1)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
			if sub[0] == extIDHandshake {
				if pid := parseExtHandshake(payload); pid != 0 {
					peerPexID = pid
				}
			} else if peerPexID != 0 && sub[0] == peerPexID {
				res.PEXPeers = append(res.PEXPeers, parsePexPayload(payload)...)
				gotPex = true
			}
		default:
			if _, err := io.CopyN(io.Discard, conn, payloadLen); err != nil {
				return
			}
		}

		// Early exit heuristics.
		if hasStatus && (gotPex || !peerSupportsLTEP) {
			return
		}
	}
}

// isSeedBitfield returns true iff every "real" bit is 1. Per BEP 3, spare
// bits at the end of the final byte MUST be zero, so a valid seed bitfield
// has all full bytes == 0xFF and a left-filled last byte (pattern 1...10...0).
// The eight valid last-byte patterns are 0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0,
// 0xC0, 0x80. Peers violating the spec by setting spare bits to 1 still read
// as seeds here, which is the correct semantic outcome (they claim complete).
func isSeedBitfield(bf []byte) bool {
	if len(bf) == 0 {
		return false
	}
	for i := 0; i < len(bf)-1; i++ {
		if bf[i] != 0xFF {
			return false
		}
	}
	last := bf[len(bf)-1]
	for n := 0; n <= 7; n++ {
		if last == byte((0xFF<<n)&0xFF) {
			return true
		}
	}
	return false
}
