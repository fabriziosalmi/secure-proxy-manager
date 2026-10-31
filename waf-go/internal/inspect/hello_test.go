package inspect

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"secure-proxy-waf/internal/engine"
)

// The first bytes of a TLS ClientHello record (16 03 01 .. .. 01), and of a
// plain-text line, base64 as Squid's %>handshake writes them (Squid 7.7).
const (
	tlsHello   = "FgMBBiABAAYcAwO9XG6NdLOty8Ug"
	plainHello = "SEVMTE8gcGxhaW4gdGV4dA0K"
)

// ParseHello fingerprints a whole ClientHello and leaves the fingerprint
// empty for a prefix or for bytes that are not one.
func TestParseHelloJA4(t *testing.T) {
	full := base64.StdEncoding.EncodeToString(record(readmeHello(), 16384))
	if h := ParseHello("www.example.org", full); h == nil || h.JA4 != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Errorf("whole hello: %+v", h)
	}
	if h := ParseHello("-", tlsHello); h == nil || !h.TLS || h.JA4 != "" {
		t.Errorf("prefix of a hello: %+v, want TLS with no JA4", h)
	}
	if h := ParseHello("-", plainHello); h == nil || h.JA4 != "" {
		t.Errorf("plain text: %+v", h)
	}
	big := base64.StdEncoding.EncodeToString(record(readmeHello(), 16384)) + strings.Repeat("A", maxHelloBase64)
	if h := ParseHello("-", big); h == nil || h.JA4 != "" {
		t.Errorf("over the bound: JA4 %q, want none", h.JA4)
	}
}

func TestParseHello(t *testing.T) {
	for _, c := range []struct {
		sni, hello string
		want       string // "nil" or "tls=.. sni=.. invalid=.."
	}{
		{"-", "-", "nil"},
		{"upstream.test", "", "nil"},
		{"-", tlsHello, "tls=true sni= invalid=false"},
		{"Upstream.Test.", tlsHello, "tls=true sni=upstream.test invalid=false"},
		{"other.test", plainHello, "tls=false sni=other.test invalid=false"},
		{"a b.test", tlsHello, "tls=true sni=a b.test invalid=true"},
		{"x..test", tlsHello, "tls=true sni=x..test invalid=true"},
		{strings.Repeat("a", 64) + ".test", tlsHello, "tls=true sni=" + strings.Repeat("a", 64) + ".test invalid=true"},
		{"my_host.example.org", tlsHello, "tls=true sni=my_host.example.org invalid=false"},
		{"upstream.test", "FgMB", "tls=false sni=upstream.test invalid=false"},
		{"upstream.test", "!!!!!!!!", "tls=false sni=upstream.test invalid=false"},
	} {
		h := ParseHello(c.sni, c.hello)
		got := "nil"
		if h != nil {
			got = fmt.Sprintf("tls=%v sni=%s invalid=%v", h.TLS, h.SNI, h.SNIInvalid)
		}
		if got != c.want {
			t.Errorf("ParseHello(%q, %q) = %s, want %s", c.sni, c.hello, got, c.want)
		}
	}
}

// The second pass of a peeked CONNECT reads only the server name: the same
// name as the CONNECT's host adds nothing, another one is a signal under the
// threshold, and that name with a second signal of its own (a generated or a
// lookalike domain) blocks. A tunnel that is not TLS adds nothing.
func TestSecondPassReadsTheServerName(t *testing.T) {
	const dga = "this-url-does-not-exist-7d1e5a90-3b2c-4f8e-9a61-c0d4e2b7f835.com"
	for _, c := range []struct {
		host, sni, hello string
		rules            string
		blocked          bool
	}{
		{"news.example.org:443", "news.example.org", tlsHello, "", false},
		{"news.example.org:443", "", tlsHello, "", false},
		{"news.example.org:443", "shop.example.net", tlsHello, "TLS-SNI-001", false},
		{"news.example.org:443", "a b", tlsHello, "TLS-SNI-001", false},
		{"my_host.example.org:443", "My_Host.Example.org", tlsHello, "", false},
		{"odd;name.example.org:443", "odd;name.example.org", tlsHello, "", false},
		{"news.example.org:443", dga, tlsHello, "TLS-SNI-001,ML-DGA-001", true},
		{"news.example.org:443", "paypa1.com", tlsHello, "TLS-SNI-001,ML-TYPO-001", true},
		{"news.example.org:443", "metadata.google.internal", tlsHello, "TLS-SNI-001,SSRF-001", true},
		{"news.example.org:443", dga, plainHello, "", false},
	} {
		r := req(t, "CONNECT "+c.host+" HTTP/1.1\r\nHost: "+c.host+"\r\n\r\n")
		in, _ := EvaluateHello(newEngine(), nil, nil, r, "192.0.2.1", ParseHello(c.sni, c.hello))
		var ids []string
		for _, m := range in.Matches {
			ids = append(ids, m.RuleID)
		}
		if got := strings.Join(ids, ","); got != c.rules || in.Blocked() != c.blocked {
			t.Errorf("CONNECT %s, SNI %q: rules [%s] blocked %v, want [%s] %v", c.host, c.sni, got, in.Blocked(), c.rules, c.blocked)
		}
	}
}

// The second pass is the request the first pass already counted: it must
// not add to a client's per-client windows. 30 hosts on the first pass and
// 30 others on the second stay under a sharding limit of 50.
func TestSecondPassSkipsTheHeuristics(t *testing.T) {
	eng := engine.New(engine.Config{BlockThreshold: 10, Heuristics: engine.HeuristicConfig{DestinationSharding: true, ShardingMaxDests: 50}})
	sharded := false
	for i := 0; i < 30; i++ {
		first := fmt.Sprintf("a%d.example.org:443", i)
		in, _ := Evaluate(eng, nil, nil, req(t, "CONNECT "+first+" HTTP/1.1\r\nHost: "+first+"\r\n\r\n"), "192.0.2.9")
		second := fmt.Sprintf("b%d.example.org:443", i)
		in2, _ := EvaluateHello(eng, nil, nil, req(t, "CONNECT "+second+" HTTP/1.1\r\nHost: "+second+"\r\n\r\n"), "192.0.2.9", ParseHello("-", tlsHello))
		for _, m := range append(in.Matches, in2.Matches...) {
			if m.RuleID == "H4-SHARDING" {
				sharded = true
			}
		}
	}
	if sharded {
		t.Fatal("the second passes were counted as destinations: H4-SHARDING fired at 30 real ones")
	}
	// Control: the same 60 hosts all on the first pass do trip it.
	eng2 := engine.New(engine.Config{BlockThreshold: 10, Heuristics: engine.HeuristicConfig{DestinationSharding: true, ShardingMaxDests: 50}})
	for i := 0; i < 60; i++ {
		h := fmt.Sprintf("c%d.example.org:443", i)
		in, _ := Evaluate(eng2, nil, nil, req(t, "CONNECT "+h+" HTTP/1.1\r\nHost: "+h+"\r\n\r\n"), "192.0.2.10")
		for _, m := range in.Matches {
			if m.RuleID == "H4-SHARDING" {
				return
			}
		}
	}
	t.Fatal("control: 60 destinations did not trip H4-SHARDING, so the test proves nothing")
}
