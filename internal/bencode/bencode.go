// Package bencode implements a minimal BitTorrent bencode decoder.
// Values become: int64, []byte (strings), []any (lists), map[string]any (dicts).
package bencode

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

var ErrUnexpectedEOF = errors.New("bencode: unexpected EOF")

type Decoder struct {
	data []byte
	pos  int
}

func NewDecoder(data []byte) *Decoder { return &Decoder{data: data} }

// Decode parses all bencoded data and returns the top-level value.
func Decode(data []byte) (any, error) {
	d := NewDecoder(data)
	v, err := d.decode()
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (d *Decoder) decode() (any, error) {
	if d.pos >= len(d.data) {
		return nil, ErrUnexpectedEOF
	}
	c := d.data[d.pos]
	switch {
	case c == 'i':
		return d.decodeInt()
	case c == 'l':
		return d.decodeList()
	case c == 'd':
		return d.decodeDict()
	case c >= '0' && c <= '9':
		return d.decodeString()
	}
	return nil, fmt.Errorf("bencode: unexpected byte %q at pos %d", c, d.pos)
}

func (d *Decoder) decodeInt() (int64, error) {
	d.pos++ // consume 'i'
	end := bytes.IndexByte(d.data[d.pos:], 'e')
	if end < 0 {
		return 0, ErrUnexpectedEOF
	}
	n, err := strconv.ParseInt(string(d.data[d.pos:d.pos+end]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bencode: bad integer: %w", err)
	}
	d.pos += end + 1
	return n, nil
}

func (d *Decoder) decodeString() ([]byte, error) {
	colon := bytes.IndexByte(d.data[d.pos:], ':')
	if colon < 0 {
		return nil, ErrUnexpectedEOF
	}
	n, err := strconv.Atoi(string(d.data[d.pos : d.pos+colon]))
	if err != nil || n < 0 {
		return nil, fmt.Errorf("bencode: bad string length")
	}
	d.pos += colon + 1
	if d.pos+n > len(d.data) {
		return nil, ErrUnexpectedEOF
	}
	s := d.data[d.pos : d.pos+n]
	d.pos += n
	return s, nil
}

func (d *Decoder) decodeList() ([]any, error) {
	d.pos++ // consume 'l'
	out := []any{}
	for {
		if d.pos >= len(d.data) {
			return nil, ErrUnexpectedEOF
		}
		if d.data[d.pos] == 'e' {
			d.pos++
			return out, nil
		}
		v, err := d.decode()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
}

func (d *Decoder) decodeDict() (map[string]any, error) {
	d.pos++ // consume 'd'
	out := map[string]any{}
	for {
		if d.pos >= len(d.data) {
			return nil, ErrUnexpectedEOF
		}
		if d.data[d.pos] == 'e' {
			d.pos++
			return out, nil
		}
		k, err := d.decodeString()
		if err != nil {
			return nil, err
		}
		v, err := d.decode()
		if err != nil {
			return nil, err
		}
		out[string(k)] = v
	}
}

// Helpers for extracting typed fields from decoded dicts.

func AsDict(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func AsInt(v any) (int64, bool) {
	n, ok := v.(int64)
	return n, ok
}

func AsBytes(v any) ([]byte, bool) {
	b, ok := v.([]byte)
	return b, ok
}

func AsString(v any) (string, bool) {
	b, ok := v.([]byte)
	if !ok {
		return "", false
	}
	return string(b), true
}

// DictInt extracts dict[key] as int64, returning (0, false) if missing or wrong type.
func DictInt(m map[string]any, key string) (int64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	return AsInt(v)
}

// DictBytes extracts dict[key] as []byte.
func DictBytes(m map[string]any, key string) ([]byte, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	return AsBytes(v)
}

// DictString extracts dict[key] as string.
func DictString(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	return AsString(v)
}
