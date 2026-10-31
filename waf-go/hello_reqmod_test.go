package main

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-icap/icap"

	"secure-proxy-waf/internal/engine"
)

// The first bytes of a TLS ClientHello and of a plain-text line, base64 as
// Squid's %>handshake writes them.
const (
	reqmodTLSHello   = "FgMBBiABAAYcAwO9XG6NdLOty8Ug"
	reqmodPlainHello = "SEVMTE8gcGxhaW4gdGV4dA0K"
)

// runConnectPass drives one CONNECT through handleReqmod with the ICAP
// headers Squid's adaptation_meta sets on the second pass ("" leaves one
// out), and returns the verdict.
func runConnectPass(t *testing.T, hostport, sni, hello string) verdict {
	t.Helper()
	prevLog := trafficLog
	trafficLog = &TrafficLogger{ch: make(chan TrafficFeature, 8)}
	defer func() { trafficLog = prevLog }()

	ireq := &icap.Request{Request: httptest.NewRequest(http.MethodConnect, hostport, nil), Header: squidHeader()}
	ireq.Header.Set("X-Client-Ip", "198.51.100.40")
	if sni != "" {
		ireq.Header.Set("X-SPM-SNI", sni)
	}
	if hello != "" {
		ireq.Header.Set("X-SPM-Client-Hello", hello)
	}
	w := &mockResponseWriter{}
	handleReqmod(w, ireq)

	v := verdict{ICAPCode: w.code}
	if resp, ok := w.resp.(*http.Response); ok && resp != nil {
		v.HTTPStatus = resp.StatusCode
	}
	select {
	case f := <-trafficLog.ch:
		v.FeatureFound = true
		v.Action = f.Action
		v.Score = f.WAFScore
		rules := append([]string(nil), f.WAFRules...)
		sort.Strings(rules)
		v.Rules = strings.Join(rules, ",")
	default:
	}
	return v
}

// A peeked CONNECT reaches the WAF twice. The first pass is an ordinary
// request; the second carries the handshake and is not a second request:
// the request total does not move, nothing is logged when nothing matched,
// and the handshake counters say what it was.
func TestConnectSecondPass(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	const dga = "this-url-does-not-exist-7d1e5a90-3b2c-4f8e-9a61-c0d4e2b7f835.com"

	for _, c := range []struct {
		name                  string
		sni, hello            string
		want                  verdict
		requests              int64
		handshakes, notTLS, m int64
	}{
		{"first pass, no handshake yet", "-", "-",
			verdict{ICAPCode: 204, Action: "allow", FeatureFound: true}, 1, 0, 0, 0},
		{"second pass, same name", "news.example.org", reqmodTLSHello,
			verdict{ICAPCode: 204}, 0, 1, 0, 0},
		{"second pass, another name", "shop.example.net", reqmodTLSHello,
			verdict{ICAPCode: 204, Action: "allow", Score: 5, Rules: "TLS-SNI-001", FeatureFound: true}, 0, 1, 0, 1},
		{"second pass, another name that looks generated", dga, reqmodTLSHello,
			verdict{ICAPCode: 200, HTTPStatus: 403, Action: "block", Score: 11, Rules: "ML-DGA-001,TLS-SNI-001", FeatureFound: true}, 0, 1, 0, 1},
		{"second pass, not TLS", "-", reqmodPlainHello,
			verdict{ICAPCode: 204}, 0, 1, 1, 0},
	} {
		req0, hs0, nt0, mm0 := stats.totalRequests.Load(), tlsHandshakes.Load(), tlsNotTLS.Load(), tlsSNIMismatch.Load()
		got := runConnectPass(t, "news.example.org:443", c.sni, c.hello)
		if got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
		if d := stats.totalRequests.Load() - req0; d != c.requests {
			t.Errorf("%s: request total moved by %d, want %d", c.name, d, c.requests)
		}
		if d := [3]int64{tlsHandshakes.Load() - hs0, tlsNotTLS.Load() - nt0, tlsSNIMismatch.Load() - mm0}; d != [3]int64{c.handshakes, c.notTLS, c.m} {
			t.Errorf("%s: handshakes, not TLS, mismatch moved by %v, want %v", c.name, d, [3]int64{c.handshakes, c.notTLS, c.m})
		}
	}
}

// Only a CONNECT has a second pass: the same headers on a decrypted GET
// (Squid sets them on every request of a bumped connection) change nothing.
func TestHandshakeHeadersOnAGetAreIgnored(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	prevLog := trafficLog
	trafficLog = &TrafficLogger{ch: make(chan TrafficFeature, 8)}
	defer func() { trafficLog = prevLog }()

	hs0 := tlsHandshakes.Load()
	ireq := &icap.Request{Request: httptest.NewRequest(http.MethodGet, "https://news.example.org/", nil), Header: squidHeader()}
	ireq.Header.Set("X-SPM-SNI", "shop.example.net")
	ireq.Header.Set("X-SPM-Client-Hello", reqmodTLSHello)
	handleReqmod(&mockResponseWriter{}, ireq)
	if d := tlsHandshakes.Load() - hs0; d != 0 {
		t.Errorf("a GET counted as a handshake (%d)", d)
	}
	select {
	case f := <-trafficLog.ch:
		if len(f.WAFRules) != 0 {
			t.Errorf("a GET with a different server name matched %v", f.WAFRules)
		}
	default:
		t.Error("the GET was not logged")
	}
}
