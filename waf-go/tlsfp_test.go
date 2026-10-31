package main

import (
	"testing"
	"time"

	"secure-proxy-waf/internal/engine"
)

// Two whole ClientHellos, base64 as Squid's %>handshake writes them: the
// JA4 README example (t13d1516h2_8daaf6152771_e5627efa2ab1) and the same
// hello without ALPN (t13d151500_8daaf6152771_e5627efa2ab1).
const (
	readmeHelloB64 = "FgMBAM0BAADJAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAoKEwETAhMDwCvAL8AswDDMqcyowBPAFACcAJ0ALwA1AQAAgBoaAAAAAAAUABIAAA93d3cuZXhhbXBsZS5vcmcAFwAA/wEAAQAACgAAAAsAAAAjAAAAEAAOAAwCaDIIaHR0cC8xLjEABQAAABIAAAAzAAAALQAAACsABwZKSgMEAwMAGwAARGkAAAAVAAAADQASABAEAwgEBAEFAwgFBQEIBgYB"
	noALPNHelloB64 = "FgMBALsBAAC3AwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAoKEwETAhMDwCvAL8AswDDMqcyowBPAFACcAJ0ALwA1AQAAbhoaAAAAAAAUABIAAA93d3cuZXhhbXBsZS5vcmcAFwAA/wEAAQAACgAAAAsAAAAjAAAABQAAABIAAAAzAAAALQAAACsABwZKSgMEAwMAGwAARGkAAAAVAAAADQASABAEAwgEBAEFAwgFBQEIBgYB"
)

func TestJA4TrackerCountsPairsPerClient(t *testing.T) {
	tr := newJA4Tracker()
	for _, c := range []struct {
		client, ja4 string
		isNew       bool
		before      int
	}{
		{"192.0.2.1", "a", true, 0},
		{"192.0.2.1", "a", false, 0},
		{"192.0.2.1", "b", true, 1},
		{"192.0.2.2", "a", true, 0},
		{"192.0.2.1", "a", false, 1},
	} {
		isNew, before, tracked := tr.observe(c.client, c.ja4)
		if isNew != c.isNew || before != c.before || !tracked {
			t.Errorf("observe(%s, %s) = %v %d %v, want %v %d true", c.client, c.ja4, isNew, before, tracked, c.isNew, c.before)
		}
	}
	if clients, pairs := tr.size(); clients != 2 || pairs != 3 {
		t.Errorf("size = %d clients, %d pairs, want 2, 3", clients, pairs)
	}
	// A client's fingerprints are bounded.
	for i := 0; i < maxJA4PerClient+5; i++ {
		tr.observe("192.0.2.3", string(rune('A'+i%26))+string(rune('a'+i/26)))
	}
	if _, _, tracked := tr.observe("192.0.2.3", "one more"); tracked {
		t.Error("a fingerprint past the per-client bound was tracked")
	}
}

func TestUALinksExpire(t *testing.T) {
	l := newUALinks()
	now := time.Now()
	l.put(uaLinkKey("192.0.2.1", "News.Example.org:443"), "curl/8.18.0", now)
	if got := l.take(uaLinkKey("192.0.2.1", "news.example.org"), now.Add(time.Second)); got != "curl/8.18.0" {
		t.Errorf("second pass (Host without port) got %q", got)
	}
	if got := l.take(uaLinkKey("192.0.2.1", "news.example.org"), now.Add(time.Second)); got != "" {
		t.Errorf("a link is taken once, got %q again", got)
	}
	l.put(uaLinkKey("192.0.2.1", "news.example.org:443"), "curl/8.18.0", now)
	if got := l.take(uaLinkKey("192.0.2.1", "news.example.org"), now.Add(uaLinkTTL+time.Second)); got != "" {
		t.Errorf("an expired link gave %q", got)
	}
}

// Through the handler: the second pass of a peeked CONNECT is fingerprinted,
// the first pass's User-Agent is linked to it, and a client showing a
// second fingerprint is counted. Nothing is scored.
func TestConnectSecondPassJA4(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	prevSeen, prevLinks := ja4Seen, uaLinks
	ja4Seen, uaLinks = newJA4Tracker(), newUALinks()
	defer func() { ja4Seen, uaLinks = prevSeen, prevLinks }()
	tlsHandshakes.Add(1) // peeked CONNECTs have been seen: first passes keep their User-Agent

	tot0, new0, unp0 := tlsJA4Total.Load(), tlsJA4NewForClient.Load(), tlsJA4Unparsed.Load()
	first := runConnectPassUA(t, "news.example.org:443", "", "", "curl/8.18.0")
	if first.Score != 0 {
		t.Fatalf("first pass scored %d", first.Score)
	}
	if got := uaLinks.m[uaLinkKey("198.51.100.40", "news.example.org")].ua; got != "curl/8.18.0" {
		t.Fatalf("the first pass kept User-Agent %q", got)
	}
	v := runConnectPassUA(t, "news.example.org:443", "news.example.org", readmeHelloB64, "")
	if v.Score != 0 || v.Action == "block" {
		t.Errorf("a fingerprint scored: %s", v)
	}
	if len(uaLinks.m) != 0 {
		t.Errorf("the second pass did not take the User-Agent (%d links left)", len(uaLinks.m))
	}
	runConnectPassUA(t, "news.example.org:443", "news.example.org", readmeHelloB64, "")
	runConnectPassUA(t, "news.example.org:443", "news.example.org", noALPNHelloB64, "")
	runConnectPassUA(t, "news.example.org:443", "news.example.org", reqmodTLSHello, "")
	if d := tlsJA4Total.Load() - tot0; d != 3 {
		t.Errorf("fingerprinted %d handshakes, want 3", d)
	}
	if d := tlsJA4NewForClient.Load() - new0; d != 1 {
		t.Errorf("new fingerprints for a known client: %d, want 1", d)
	}
	if d := tlsJA4Unparsed.Load() - unp0; d != 1 {
		t.Errorf("unparsed: %d, want 1 (a prefix of a hello)", d)
	}
	if clients, pairs := ja4Seen.size(); clients != 1 || pairs != 2 {
		t.Errorf("tracker holds %d clients, %d pairs, want 1, 2", clients, pairs)
	}
}
