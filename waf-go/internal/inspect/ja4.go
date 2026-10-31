package inspect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// JA4 is the FoxIO JA4 fingerprint of a TLS ClientHello carried over TCP:
// "t", the highest TLS version offered, "d" when the hello names a server
// (else "i"), the cipher and extension counts, the first and last character
// of the first ALPN value; then the truncated SHA-256 of the sorted cipher
// suites; then that of the sorted extensions (without SNI and ALPN) and the
// signature algorithms in their order. GREASE values are left out
// everywhere. hello is what Squid's %>handshake holds: the TLS records the
// client sent first.
func JA4(hello []byte) (string, error) {
	ch, err := parseClientHello(hello)
	if err != nil {
		return "", err
	}
	var ciphers, exts, sorted []string
	for _, c := range ch.ciphers {
		if !isGREASE(c) {
			ciphers = append(ciphers, fmt.Sprintf("%04x", c))
		}
	}
	sni, alpn := "i", "00"
	for _, e := range ch.extensions {
		if isGREASE(e) {
			continue
		}
		exts = append(exts, fmt.Sprintf("%04x", e))
		switch e {
		case 0x0000:
			sni = "d"
		case 0x0010:
		default:
			sorted = append(sorted, fmt.Sprintf("%04x", e))
		}
	}
	if ch.alpn != "" {
		alpn = alpnChars(ch.alpn)
	}
	sort.Strings(ciphers)
	sort.Strings(sorted)
	var sigs []string
	for _, s := range ch.sigAlgs {
		if !isGREASE(s) {
			sigs = append(sigs, fmt.Sprintf("%04x", s))
		}
	}
	b := strings.Join(ciphers, ",")
	c := strings.Join(sorted, ",")
	if len(sigs) > 0 {
		c += "_" + strings.Join(sigs, ",")
	}
	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s", tlsVersion(ch), sni, min(len(ciphers), 99), min(len(exts), 99), alpn,
		hash12(b, len(ciphers) == 0), hash12(c, len(sorted) == 0)), nil
}

// hash12 is the first 12 hex characters of the SHA-256 of s, or twelve
// zeros when there was nothing to hash.
func hash12(s string, empty bool) string {
	if empty {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// isGREASE reports a GREASE value (RFC 8701): 0x?a?a with both bytes equal.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// alpnChars is the first and last character of an ALPN value, or of its hex
// form when either is not a letter or a digit.
func alpnChars(v string) string {
	first, last := v[0], v[len(v)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	h := hex.EncodeToString([]byte(v))
	return string([]byte{h[0], h[len(h)-1]})
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// tlsVersion is the highest version the hello offers: from the
// supported_versions extension when present (GREASE left out), else the
// hello's own version field.
func tlsVersion(ch *clientHello) string {
	v := ch.version
	if len(ch.versions) > 0 {
		v = 0
		for _, x := range ch.versions {
			if !isGREASE(x) && x > v {
				v = x
			}
		}
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	}
	return "00"
}

type clientHello struct {
	version    uint16
	ciphers    []uint16
	extensions []uint16
	versions   []uint16 // supported_versions (43)
	sigAlgs    []uint16 // signature_algorithms (13), in order
	alpn       string   // first ALPN protocol (16)
}

var errNotClientHello = errors.New("not a TLS ClientHello")

// parseClientHello reads a ClientHello from TLS records. A hello split over
// several handshake records is joined first; anything that does not parse
// in full is an error rather than a partial fingerprint.
func parseClientHello(b []byte) (*clientHello, error) {
	var msg []byte
	for len(b) >= 5 && b[0] == 0x16 {
		n := int(b[3])<<8 | int(b[4])
		if len(b) < 5+n {
			return nil, errNotClientHello
		}
		msg = append(msg, b[5:5+n]...)
		b = b[5+n:]
		if len(msg) >= 4 && len(msg) >= 4+(int(msg[1])<<16|int(msg[2])<<8|int(msg[3])) {
			break
		}
	}
	if len(msg) < 4 || msg[0] != 0x01 {
		return nil, errNotClientHello
	}
	n := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if len(msg) < 4+n {
		return nil, errNotClientHello
	}
	r := reader(msg[4 : 4+n])
	ch := &clientHello{}
	var ok bool
	if ch.version, ok = r.u16(); !ok {
		return nil, errNotClientHello
	}
	if !r.skip(32) || !r.skip8() {
		return nil, errNotClientHello
	}
	cs, ok := r.vec16()
	if !ok || len(cs)%2 != 0 {
		return nil, errNotClientHello
	}
	for i := 0; i < len(cs); i += 2 {
		ch.ciphers = append(ch.ciphers, uint16(cs[i])<<8|uint16(cs[i+1]))
	}
	if !r.skip8() {
		return nil, errNotClientHello
	}
	if len(r) == 0 {
		return ch, nil // no extensions at all
	}
	exts, ok := r.vec16()
	if !ok {
		return nil, errNotClientHello
	}
	e := reader(exts)
	for len(e) > 0 {
		typ, ok := e.u16()
		if !ok {
			return nil, errNotClientHello
		}
		data, ok := e.vec16()
		if !ok {
			return nil, errNotClientHello
		}
		ch.extensions = append(ch.extensions, typ)
		d := reader(data)
		switch typ {
		case 0x000d:
			v, ok := d.vec16()
			if !ok || len(v)%2 != 0 {
				return nil, errNotClientHello
			}
			for i := 0; i < len(v); i += 2 {
				ch.sigAlgs = append(ch.sigAlgs, uint16(v[i])<<8|uint16(v[i+1]))
			}
		case 0x0010:
			list, ok := d.vec16()
			if !ok {
				return nil, errNotClientHello
			}
			l := reader(list)
			if p, ok := l.vec8(); ok && len(p) > 0 {
				ch.alpn = string(p)
			}
		case 0x002b:
			v, ok := d.vec8()
			if !ok || len(v)%2 != 0 {
				return nil, errNotClientHello
			}
			for i := 0; i < len(v); i += 2 {
				ch.versions = append(ch.versions, uint16(v[i])<<8|uint16(v[i+1]))
			}
		}
	}
	return ch, nil
}

// reader consumes a byte slice front to back; every read reports whether
// the bytes were there.
type reader []byte

func (r *reader) u16() (uint16, bool) {
	if len(*r) < 2 {
		return 0, false
	}
	v := uint16((*r)[0])<<8 | uint16((*r)[1])
	*r = (*r)[2:]
	return v, true
}

func (r *reader) skip(n int) bool {
	if len(*r) < n {
		return false
	}
	*r = (*r)[n:]
	return true
}

func (r *reader) skip8() bool {
	_, ok := r.vec8()
	return ok
}

func (r *reader) vec8() ([]byte, bool) {
	if len(*r) < 1 {
		return nil, false
	}
	n := int((*r)[0])
	if len(*r) < 1+n {
		return nil, false
	}
	v := (*r)[1 : 1+n]
	*r = (*r)[1+n:]
	return v, true
}

func (r *reader) vec16() ([]byte, bool) {
	if len(*r) < 2 {
		return nil, false
	}
	n := int((*r)[0])<<8 | int((*r)[1])
	if len(*r) < 2+n {
		return nil, false
	}
	v := (*r)[2 : 2+n]
	*r = (*r)[2+n:]
	return v, true
}
