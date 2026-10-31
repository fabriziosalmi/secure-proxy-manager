package inspect

import (
	"encoding/binary"
	"strings"
	"testing"
)

type ext struct {
	typ  uint16
	data []byte
}

func u16s(vs ...uint16) []byte {
	b := make([]byte, 2*len(vs))
	for i, v := range vs {
		binary.BigEndian.PutUint16(b[2*i:], v)
	}
	return b
}

func vec16(b []byte) []byte { return append(u16s(uint16(len(b))), b...) }
func vec8(b []byte) []byte  { return append([]byte{byte(len(b))}, b...) }

// buildHello writes a ClientHello handshake message from its parts.
func buildHello(version uint16, ciphers []uint16, exts []ext) []byte {
	body := u16s(version)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, vec8(nil)...)        // session id
	body = append(body, vec16(u16s(ciphers...))...)
	body = append(body, vec8([]byte{0})...) // compression: null
	var e []byte
	for _, x := range exts {
		e = append(e, u16s(x.typ)...)
		e = append(e, vec16(x.data)...)
	}
	body = append(body, vec16(e)...)
	n := len(body)
	return append([]byte{0x01, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

// record wraps handshake bytes in TLS records of at most max bytes each.
func record(msg []byte, max int) []byte {
	var out []byte
	for len(msg) > 0 {
		n := min(len(msg), max)
		out = append(out, 0x16, 0x03, 0x01, byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

func sni(name string) ext {
	entry := append([]byte{0}, vec16([]byte(name))...)
	return ext{0x0000, vec16(entry)}
}

func alpn(protos ...string) ext {
	var l []byte
	for _, p := range protos {
		l = append(l, vec8([]byte(p))...)
	}
	return ext{0x0010, vec16(l)}
}

// readmeHello is the example of the JA4 README (FoxIO): 15 cipher suites,
// 16 extensions with SNI and ALPN h2, TLS 1.3, and its signature algorithms
// in order; JA4 t13d1516h2_8daaf6152771_e5627efa2ab1. GREASE values are
// added in a cipher, an extension and the supported versions, as Chrome
// sends them; JA4 leaves them out.
func readmeHello(drop ...uint16) []byte {
	ciphers := []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	exts := []ext{
		{0x1a1a, nil},
		sni("www.example.org"),
		{0x0017, nil}, {0xff01, []byte{0}}, {0x000a, nil}, {0x000b, nil}, {0x0023, nil},
		alpn("h2", "http/1.1"),
		{0x0005, nil}, {0x0012, nil}, {0x0033, nil}, {0x002d, nil},
		{0x002b, vec8(u16s(0x4a4a, 0x0304, 0x0303))},
		{0x001b, nil}, {0x4469, nil}, {0x0015, nil},
		{0x000d, vec16(u16s(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601))},
	}
	var kept []ext
	for _, e := range exts {
		skip := false
		for _, d := range drop {
			if e.typ == d {
				skip = true
			}
		}
		if !skip {
			kept = append(kept, e)
		}
	}
	return buildHello(0x0303, ciphers, kept)
}

func TestJA4(t *testing.T) {
	for _, c := range []struct {
		name  string
		hello []byte
		want  string
	}{
		{"the README example", record(readmeHello(), 16384), "t13d1516h2_8daaf6152771_e5627efa2ab1"},
		{"split over two records", record(readmeHello(), 100), "t13d1516h2_8daaf6152771_e5627efa2ab1"},
		// SNI and ALPN are counted but not hashed: only part a changes.
		{"no server name", record(readmeHello(0x0000), 16384), "t13i1515h2_8daaf6152771_e5627efa2ab1"},
		{"no ALPN", record(readmeHello(0x0010), 16384), "t13d151500_8daaf6152771_e5627efa2ab1"},
		{"no supported_versions: the hello's own version", record(readmeHello(0x002b), 16384), "t12d1515h2_8daaf6152771_"},
		{"an ALPN that is not letters", record(buildHello(0x0303, []uint16{0x1301}, []ext{alpn("\xab\x01\xcd")}), 16384), "t12i0101ad_"},
		{"no extensions", record(buildHello(0x0303, []uint16{0x1301}, nil), 16384), "t12i0100" + "00_"},
	} {
		got, err := JA4(c.hello)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !strings.HasPrefix(got, c.want) {
			t.Errorf("%s: JA4 %s, want %s...", c.name, got, c.want)
		}
	}
	// Without signature algorithms the third part has no underscore and its
	// hash changes; with no extension left to hash it is twelve zeros.
	if got, _ := JA4(record(buildHello(0x0303, []uint16{0x1301}, nil), 16384)); !strings.HasSuffix(got, "_000000000000") {
		t.Errorf("no extensions: %s, want a part c of zeros", got)
	}
}

func TestJA4RefusesWhatIsNotAHello(t *testing.T) {
	full := record(readmeHello(), 16384)
	for name, b := range map[string][]byte{
		"empty":            nil,
		"plain text":       []byte("HELLO plain text\r\n"),
		"truncated record": full[:len(full)-10],
		"server hello":     record(append([]byte{0x02}, buildHello(0x0303, nil, nil)[1:]...), 16384),
		"short extension":  record(buildHello(0x0303, []uint16{0x1301}, []ext{{0x000d, []byte{0x00, 0x09, 0x04}}}), 16384),
	} {
		if got, err := JA4(b); err == nil {
			t.Errorf("%s: JA4 %s, want an error", name, got)
		}
	}
}

func TestIsGREASE(t *testing.T) {
	for v, want := range map[uint16]bool{0x0a0a: true, 0x1a1a: true, 0xfafa: true, 0x0a1a: false, 0x1301: false, 0x0000: false} {
		if isGREASE(v) != want {
			t.Errorf("isGREASE(%#04x) = %v", v, !want)
		}
	}
}
