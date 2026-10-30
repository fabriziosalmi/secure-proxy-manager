package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-icap/icap"

	"secure-proxy-waf/internal/engine"
)

// H3: a response carrying more than WAF_H_PII_MAX (5) PII items is blocked;
// email addresses count. This pins the branch of the response verdict that
// no other test reached.
func TestRespmodPIIHeuristic(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10, Heuristics: engine.HeuristicsFromEnv()})
	page := func(n int) *http.Response {
		var b strings.Builder
		b.WriteString("<html><body><h1>Team</h1><ul>")
		for i := 0; i < n; i++ {
			b.WriteString("<li>person" + itoa(i) + "@example.org</li>")
		}
		b.WriteString("</ul></body></html>")
		return &http.Response{StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(bytes.NewReader([]byte(b.String())))}
	}
	blocked := func(n int) bool {
		w := &mockResponseWriter{}
		handleRespmod(w, &icap.Request{Method: "RESPMOD", Response: page(n), Header: squidHeader()})
		r, ok := w.resp.(*http.Response)
		return ok && r.StatusCode == http.StatusForbidden
	}
	if blocked(5) {
		t.Error("5 email addresses blocked the response; the limit is more than 5")
	}
	if !blocked(6) {
		t.Error("6 email addresses did not block the response")
	}
}
