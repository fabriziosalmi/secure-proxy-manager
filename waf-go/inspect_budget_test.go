package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/go-icap/icap"

	"secure-proxy-waf/internal/budget"
	"secure-proxy-waf/internal/engine"
)

// withBudget sets the inspection budget and the wait for one test, and holds
// `held` bytes of it as concurrent inspections would.
func withBudget(t *testing.T, total, held int64, wait time.Duration) *budget.Budget {
	t.Helper()
	prevB, prevW := inspectBudget, budgetWait
	b := budget.New(total)
	inspectBudget, budgetWait = b, wait
	var n int64
	if held > 0 {
		n, _ = b.Acquire(context.Background(), held)
	}
	t.Cleanup(func() {
		b.Release(n)
		inspectBudget, budgetWait = prevB, prevW
	})
	return b
}

func withFailOpen(t *testing.T, on bool) {
	t.Helper()
	prev := wafFailOpen
	wafFailOpen = on
	t.Cleanup(func() { wafFailOpen = prev })
}

func bodyReqmod(t *testing.T, body string) *mockResponseWriter {
	t.Helper()
	return typedReqmod(t, "text/plain", body)
}

func typedReqmod(t *testing.T, contentType, body string) *mockResponseWriter {
	t.Helper()
	r := httptest.NewRequest("POST", "http://upstream.example/submit", strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	w := &mockResponseWriter{}
	handleReqmod(w, &icap.Request{Method: "REQMOD", Request: r, Header: squidHeader()})
	return w
}

func httpStatus(w *mockResponseWriter) int {
	if r, ok := w.resp.(*http.Response); ok {
		return r.StatusCode
	}
	return 0
}

// The fault the budget closes: with the budget spent by other inspections,
// a 1 MiB body is not read into memory. After the wait it is refused with a
// 503, fail closed, instead of being inspected on top of the others.
func TestReqmodBodyOverTheBudgetIsRefused(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withFailOpen(t, false)
	b := withBudget(t, inspectBudgetFloor, inspectBudgetFloor, 50*time.Millisecond)
	before := budgetRefused.Load()

	start := time.Now()
	w := bodyReqmod(t, benignBody(maxBodyInspectSize))
	if w.code != 200 || httpStatus(w) != http.StatusServiceUnavailable {
		t.Fatalf("ICAP %d carrying HTTP %d, want 200 carrying 503", w.code, httpStatus(w))
	}
	if d := time.Since(start); d < 40*time.Millisecond {
		t.Errorf("refused after %v, without waiting for the budget", d)
	}
	if got := budgetRefused.Load() - before; got != 1 {
		t.Errorf("refusals counted: %d, want 1", got)
	}
	if b.Used() != inspectBudgetFloor {
		t.Errorf("budget used %d after a refusal, want only what was held", b.Used())
	}
}

// WAF_FAIL_OPEN=1 trades inspection for availability: the request passes.
func TestReqmodBodyOverTheBudgetPassesWithFailOpen(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withFailOpen(t, true)
	withBudget(t, inspectBudgetFloor, inspectBudgetFloor, 20*time.Millisecond)
	if w := bodyReqmod(t, benignBody(4096)); w.code != 204 {
		t.Fatalf("ICAP %d carrying HTTP %d, want a 204 pass", w.code, httpStatus(w))
	}
}

// A request without a body reserves nothing: a spent budget does not hold it.
func TestReqmodWithoutABodyIsNotHeldByTheBudget(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withBudget(t, inspectBudgetFloor, inspectBudgetFloor, 2*time.Second)
	r := httptest.NewRequest("GET", "http://upstream.example/", nil)
	w := &mockResponseWriter{}
	start := time.Now()
	handleReqmod(w, &icap.Request{Method: "REQMOD", Request: r, Header: squidHeader()})
	if w.code != 204 {
		t.Fatalf("ICAP %d, want 204", w.code)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("a GET waited %v for the body budget", d)
	}
}

// What a request reserved is given back when it is answered, blocked or not.
func TestReqmodGivesBackItsReservation(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	b := withBudget(t, 8*maxBodyInspectSize, 0, time.Second)
	if w := bodyReqmod(t, benignBody(300000)); w.code != 204 {
		t.Fatalf("benign body: ICAP %d, want 204", w.code)
	}
	if w := typedReqmod(t, "application/x-www-form-urlencoded", "q=1' UNION SELECT password FROM users--"); w.code != 200 || httpStatus(w) != 403 {
		t.Fatalf("injection: ICAP %d carrying HTTP %d, want 200 carrying 403", w.code, httpStatus(w))
	}
	if b.Used() != 0 {
		t.Errorf("budget used %d after both requests were answered, want 0", b.Used())
	}
}

// A text response over the budget passes uninspected, as a response does
// when the WAF cannot be reached (RESPMOD bypass=1); it is counted.
func TestRespmodOverTheBudgetPasses(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withBudget(t, inspectBudgetFloor, inspectBudgetFloor, 20*time.Millisecond)
	before := respmodOverBudget.Load()
	body := benignBody(maxBodyInspectSize)
	resp := &http.Response{
		StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": {"text/html"}},
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(bytes.NewReader([]byte(body))),
	}
	w := &mockResponseWriter{}
	handleRespmod(w, &icap.Request{Method: "RESPMOD", Response: resp, Header: textproto.MIMEHeader{"Allow": {"trailers"}}})
	if w.code != 200 || w.body.String() != body {
		t.Fatalf("ICAP %d with %d of %d bytes, want 200 with the response whole", w.code, w.body.Len(), len(body))
	}
	if got := respmodOverBudget.Load() - before; got != 1 {
		t.Errorf("responses passed over the budget: %d, want 1", got)
	}
}

// An image is never read by the response rules, so it reserves nothing.
func TestRespmodBinaryIsNotHeldByTheBudget(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withBudget(t, inspectBudgetFloor, inspectBudgetFloor, 2*time.Second)
	before := respmodOverBudget.Load()
	resp := &http.Response{
		StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": {"image/png"}},
		ContentLength: 500000,
		Body:          io.NopCloser(bytes.NewReader(make([]byte, 500000))),
	}
	w := &mockResponseWriter{}
	start := time.Now()
	handleRespmod(w, &icap.Request{Method: "RESPMOD", Response: resp, Header: squidHeader()})
	if w.code != 204 || time.Since(start) > time.Second {
		t.Fatalf("ICAP %d after %v, want an immediate 204", w.code, time.Since(start))
	}
	if respmodOverBudget.Load() != before {
		t.Error("an image was counted as passed over the budget")
	}
}

func TestBodyWeight(t *testing.T) {
	limit := int64(maxBodyInspectSize+1) + inspectFixedWeight
	fixed := int64(inspectFixedWeight)
	cases := []struct {
		name string
		enc  string
		cl   int64
		body io.ReadCloser
		want int64
	}{
		{"no body", "", 0, nil, 0},
		{"NoBody", "", 0, http.NoBody, 0},
		{"null-body from Squid", "req-hdr=0, null-body=120", 0, io.NopCloser(strings.NewReader("")), 0},
		{"small, length known", "req-hdr=0, req-body=120", 500, io.NopCloser(strings.NewReader("x")), fixed + 500},
		{"large, length known", "req-hdr=0, req-body=120", 50 << 20, io.NopCloser(strings.NewReader("x")), limit},
		{"chunked, length unknown", "req-hdr=0, req-body=120", -1, io.NopCloser(strings.NewReader("x")), limit},
		{"body announced, length 0", "req-hdr=0, req-body=120", 0, io.NopCloser(strings.NewReader("x")), limit},
		{"response body", "res-hdr=0, res-body=200", 700, io.NopCloser(strings.NewReader("x")), fixed + 700},
	}
	for _, c := range cases {
		hdr := textproto.MIMEHeader{}
		if c.enc != "" {
			hdr.Set("Encapsulated", c.enc)
		}
		if got := bodyWeight(hdr, c.cl, c.body); got != c.want {
			t.Errorf("%s: weight %d, want %d", c.name, got, c.want)
		}
	}
}
