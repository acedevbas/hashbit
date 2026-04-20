package dht

import (
	"crypto/rand"
	"hash/crc32"
	"net"
)

// castagnoliTable is shared by every BEP 42 id derivation. crc32.MakeTable is
// cheap but documented as "intended to be cached" — a package-level table
// avoids pointless reallocation on hot rekey paths.
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// bep42NodeID derives a node id bound to the supplied public IPv4 address per
// BEP 42. Modern DHT stacks (libtorrent 1.2+, BiglyBT) score peers by how
// strictly their advertised id matches this derivation and silently drop or
// downweight queries from "weak" ids, so running without a derived id
// measurably shrinks our effective reply rate.
//
// The low 3 bits of the id are a freely chosen random nonce r; the rest is
// anchored to the first four IP octets masked down to the bits that BEP 42
// declares significant.
func bep42NodeID(ip4 net.IP) (NodeID, error) {
	var id NodeID
	ip4 = ip4.To4()
	if ip4 == nil {
		// Fall back to a purely random id if we somehow got a non-IPv4 address;
		// the caller chose to opt into BEP 42 but we can't derive without v4.
		_, err := rand.Read(id[:])
		return id, err
	}

	var rnd [18]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return id, err
	}
	r := rnd[0] & 0x07

	masked := [4]byte{
		(ip4[0] & 0x03) | (r << 5),
		ip4[1] & 0x0f,
		ip4[2] & 0x3f,
		ip4[3],
	}
	crc := crc32.Checksum(masked[:], castagnoliTable)

	id[0] = byte(crc >> 24)
	id[1] = byte(crc >> 16)
	// High 5 bits of byte 2 carry CRC bits 11..15; low 3 bits are random noise
	// so each (ip, r) pair can still produce 2^131 distinct valid ids.
	id[2] = byte((crc>>8)&0xf8) | (rnd[1] & 0x07)
	copy(id[3:19], rnd[2:18])
	id[19] = r
	return id, nil
}

// extractObservedIPv4 parses BEP 42's response-echo field: a responder that
// implements the spec copies the requester's apparent public endpoint into
// the top-level "ip" key as 6 bytes (IPv4) or 18 bytes (IPv6). Only the v4
// form is useful for id derivation here.
func extractObservedIPv4(top map[string]any) net.IP {
	raw, ok := top["ip"]
	if !ok {
		return nil
	}
	b, ok := raw.([]byte)
	if !ok || len(b) < 4 {
		return nil
	}
	ip := net.IPv4(b[0], b[1], b[2], b[3])
	if !usableIP(ip) {
		return nil
	}
	return ip
}
