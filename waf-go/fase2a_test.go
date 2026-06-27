package main

import (
	"io"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-icap/icap"
)

func nopRC(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }

func mustCompileCI(p string) *regexp.Regexp { return regexp.MustCompile("(?i)" + p) }

// Comment-based and homoglyph evasions must be normalized so the existing
// signature rules still fire. We feed input through the same normalize → match
// path the handler uses.
func TestNormalizationDefeatsEvasion(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		block bool
	}{
		{"plain UNION SELECT", "a=1 UNION SELECT password FROM users", true},
		{"inline-comment SQLi", "a=1 UNION/**/SELECT password FROM users", true},
		{"multi-comment SQLi", "a=1 UN/**/ION/**/SELECT x", false}, // UN ION is not the UNION keyword — must NOT false-positive
		{"plain script tag", "<script>alert(1)</script>", true},
		{"html-comment split script", "<scr<!-- -->ipt>alert(1)", true},
		{"fullwidth script tag", "＜script＞alert(1)", true}, // ＜script＞ via NFKC
		{"benign query", "q=hello+world&lang=en", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			norm := normalizeInput(c.raw)
			_, score := matchRulesScored(norm)
			blocked := score >= blockThreshold
			if blocked != c.block {
				t.Errorf("raw=%q normalized=%q score=%d blocked=%v want %v", c.raw, norm, score, blocked, c.block)
			}
		})
	}
}

func TestIsCompressedEncoding(t *testing.T) {
	for _, e := range []string{"gzip", "br", "deflate", "compress", "zstd", "GZIP", " gzip "} {
		if !isCompressedEncoding(e) {
			t.Errorf("isCompressedEncoding(%q) = false, want true", e)
		}
	}
	for _, e := range []string{"", "identity", "  "} {
		if isCompressedEncoding(e) {
			t.Errorf("isCompressedEncoding(%q) = true, want false", e)
		}
	}
}

// A request body larger than the inspection limit must be flagged (counter +
// corroborating signal), not silently allowed.
func TestOversizeBodyFlagged(t *testing.T) {
	before := bodyTruncatedCount.Load()
	big := strings.Repeat("A", maxBodyInspectSize+1024) // benign padding, over the limit
	req := &icap.Request{
		Request: httptest.NewRequest("POST", "http://example.com/upload", strings.NewReader(big)),
	}
	req.Request.Header.Set("Content-Type", "text/plain")
	w := &mockResponseWriter{}
	handleReqmod(w, req)

	if got := bodyTruncatedCount.Load(); got != before+1 {
		t.Errorf("bodyTruncatedCount = %d, want %d", got, before+1)
	}
	// Benign padding + the oversize signal alone must NOT block (signal < threshold).
	if w.code == 200 {
		t.Error("benign oversize body should not block on the oversize signal alone")
	}
}

// A compressed text response is uninspectable; the WAF must count it and pass
// the response through (204) rather than scanning compressed bytes.
func TestRespmodCompressedIsUninspectable(t *testing.T) {
	before := respmodUninspectable.Load()
	resp := httptest.NewRecorder().Result()
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Set("Content-Encoding", "gzip")
	resp.Body = nopRC("\x1f\x8b\x08 compressed bytes here")
	req := &icap.Request{Response: resp}
	w := &mockResponseWriter{}
	handleRespmod(w, req)

	if w.code != 204 {
		t.Errorf("expected 204 passthrough, got %d", w.code)
	}
	if got := respmodUninspectable.Load(); got != before+1 {
		t.Errorf("respmodUninspectable = %d, want %d", got, before+1)
	}
}

func TestOverlyBroadRule(t *testing.T) {
	broad := []string{".*", ".+", "", "a?", "(?i).*", "[\\s\\S]*", ".{0,}"}
	ok := []string{"union\\s+select", "<script", "etc/passwd", "\\.\\./"}
	for _, p := range broad {
		re := mustCompileCI(p)
		if reason := overlyBroadRule(re); reason == "" {
			t.Errorf("overlyBroadRule(%q) accepted a catch-all pattern", p)
		}
	}
	for _, p := range ok {
		re := mustCompileCI(p)
		if reason := overlyBroadRule(re); reason != "" {
			t.Errorf("overlyBroadRule(%q) rejected a specific pattern: %s", p, reason)
		}
	}
}
