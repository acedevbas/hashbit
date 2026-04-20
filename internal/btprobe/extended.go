// PEX (BEP 11) + BEP 10 Extended Protocol support.
//
// The flow after a successful BitTorrent handshake is:
//  1. We send an extended handshake advertising our internal id for ut_pex.
//  2. Peer replies with its own extended handshake. Its "m" dict tells us
//     the id it uses for ut_pex on its side.
//  3. Peer spontaneously sends a ut_pex message (id = whatever it advertised)
//     containing up to 50 compact peer endpoints under "added"/"added6".
//
// Per BEP 11 a client must not send more than one ut_pex per minute, but the
// initial message ships immediately on most clients (qBittorrent, libtorrent,
// uTorrent, Transmission) so a 3-5 second read window captures it.

package btprobe

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/acedevbas/hashbit/internal/bencode"
)

const (
	msgLTEP        byte = 20 // BEP 10 extended message id
	extIDHandshake byte = 0  // sub-id 0 is reserved for the extended handshake itself
	ourPexID       byte = 1  // internal id we publish for ut_pex
)

// extHandshakeFrame is a precomputed frame advertising ut_pex=1.
// Bencoded payload: d1:md6:ut_pexi1eee (18 bytes), wrapped in the BEP 10
// extended-message envelope (4-byte length, 1-byte msg id=20, 1-byte sub id=0).
var extHandshakeFrame = func() []byte {
	payload := []byte("d1:md6:ut_pexi1eee")
	frame := make([]byte, 4+2+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], uint32(2+len(payload)))
	frame[4] = msgLTEP
	frame[5] = extIDHandshake
	copy(frame[6:], payload)
	return frame
}()

// parseExtHandshake pulls the peer's internal id for ut_pex out of its BEP 10
// handshake payload. Returns 0 when the peer does not speak ut_pex.
func parseExtHandshake(payload []byte) byte {
	v, err := bencode.Decode(payload)
	if err != nil {
		return 0
	}
	top, ok := bencode.AsDict(v)
	if !ok {
		return 0
	}
	m, ok := bencode.AsDict(top["m"])
	if !ok {
		return 0
	}
	id, ok := bencode.DictInt(m, "ut_pex")
	if !ok || id < 1 || id > 255 {
		return 0
	}
	return byte(id)
}

// parsePexPayload extracts peer endpoints from a ut_pex message body.
// "added" carries 6-byte compact IPv4, "added6" carries 18-byte compact IPv6.
// Dropped / flag fields are ignored — we only care about positive contacts.
func parsePexPayload(payload []byte) []string {
	v, err := bencode.Decode(payload)
	if err != nil {
		return nil
	}
	top, ok := bencode.AsDict(v)
	if !ok {
		return nil
	}
	var peers []string
	if added, ok := bencode.DictBytes(top, "added"); ok {
		for i := 0; i+6 <= len(added); i += 6 {
			ip := net.IPv4(added[i], added[i+1], added[i+2], added[i+3])
			port := binary.BigEndian.Uint16(added[i+4 : i+6])
			if port == 0 || !usableIP(ip) {
				continue
			}
			peers = append(peers, fmt.Sprintf("%s:%d", ip.To4(), port))
		}
	}
	if added6, ok := bencode.DictBytes(top, "added6"); ok {
		for i := 0; i+18 <= len(added6); i += 18 {
			ip := net.IP(append([]byte(nil), added6[i:i+16]...))
			port := binary.BigEndian.Uint16(added6[i+16 : i+18])
			if port == 0 || !usableIP(ip) {
				continue
			}
			peers = append(peers, fmt.Sprintf("[%s]:%d", ip, port))
		}
	}
	return peers
}

func usableIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}
