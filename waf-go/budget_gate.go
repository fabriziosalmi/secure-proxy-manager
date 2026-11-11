package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/textproto"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-icap/icap"

	"secure-proxy-waf/internal/budget"
	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/inspect"
)

const (
	// inspectCostPerByte is what one inspected body byte costs in memory, all
	// copies counted, rounded up from measurements on the waf image under its
	// 256 MiB limit: about 11 bytes per byte on the go regex engine and about
	// 14 on re2, with 1 MiB bodies.
	inspectCostPerByte = 20
	// fallbackInspectBudget applies when the container has no memory limit.
	fallbackInspectBudget = 64 << 20
	// inspectFixedWeight is what an inspection costs whatever its body size
	// (the CRS transaction, the per-request copies), in budget bytes: about
	// 1 MiB of memory per request measured with 16 KiB bodies on re2, divided
	// by inspectCostPerByte and rounded up. Without it, a hundred small
	// bodies fit in the budget at once and took re2 to 246 of its 256 MiB.
	inspectFixedWeight = 64 << 10
	// inspectBudgetFloor lets one body of the largest inspected size in.
	inspectBudgetFloor = maxBodyInspectSize + 1 + inspectFixedWeight
)

var (
	// inspectBudget bounds the body bytes inspected at once; main sizes it
	// from the container's memory limit (internal/budget).
	inspectBudget = budget.New(fallbackInspectBudget)
	// budgetWait is how long a body waits for the budget before it is
	// refused (REQMOD) or passed uninspected (RESPMOD).
	budgetWait = 30 * time.Second

	budgetWaited      atomic.Int64 // bodies that had to wait for the budget
	budgetRefused     atomic.Int64 // REQMOD bodies refused with a 503 after the wait
	budgetFailOpen    atomic.Int64 // REQMOD bodies passed uninspected after the wait (WAF_FAIL_OPEN=1)
	respmodOverBudget atomic.Int64 // RESPMOD bodies passed uninspected after the wait
)

// bodyWeight is what an inspection of this message reserves: nothing without
// a body; otherwise inspectFixedWeight plus the bytes it reads, its length
// when known, else the most the WAF reads (MaxBodyInspectSize plus the byte
// that tells a truncated body).
func bodyWeight(icapHeader textproto.MIMEHeader, contentLength int64, body io.ReadCloser) int64 {
	if body == nil || body == http.NoBody {
		return 0
	}
	if enc := icapHeader.Get("Encapsulated"); enc != "" {
		if !strings.Contains(enc, "req-body=") && !strings.Contains(enc, "res-body=") {
			return 0
		}
	} else if contentLength == 0 {
		return 0
	}
	limit := int64(maxBodyInspectSize + 1)
	if contentLength > 0 && contentLength < limit {
		return inspectFixedWeight + contentLength
	}
	return inspectFixedWeight + limit
}

// reserveWeight waits for n bytes of the inspection budget. It returns the
// function that gives them back, and false when the wait ran out.
func reserveWeight(n int64) (func(), bool) {
	if n <= 0 {
		return func() {}, true
	}
	b := inspectBudget
	// A context that is already done takes the bytes only if they fit now.
	done, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	got, ok := b.Acquire(done, n)
	if !ok {
		budgetWaited.Add(1)
		ctx, cancel := context.WithTimeout(context.Background(), budgetWait)
		got, ok = b.Acquire(ctx, n)
		cancel()
	}
	if !ok {
		return func() {}, false
	}
	return func() { b.Release(got) }, true
}

// configureInspectBudget sizes the budget from the container's memory limit,
// and sets the Go runtime's soft memory limit to 90% of it (unless GOMEMLIMIT
// is set), so the collector works harder before the kernel kills the process.
func configureInspectBudget() {
	total, limit := budget.Size("/sys/fs/cgroup", inspectCostPerByte, inspectBudgetFloor, fallbackInspectBudget)
	inspectBudget = budget.New(total)
	if limit > 0 && os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(limit / 10 * 9)
	}
	slog.Info("WAF inspection budget", "budget_bytes", total, "memory_limit_bytes", limit,
		"cost_per_byte", inspectCostPerByte, "wait", budgetWait.String())
}

// lastBudgetLog rate-limits the over-budget log line: a client that sends
// bodies in a loop would otherwise write one per request.
var lastBudgetLog atomic.Int64

func logOverBudget(method, outcome string, req *icap.Request) {
	now := time.Now().UnixNano()
	last := lastBudgetLog.Load()
	if now-last < int64(10*time.Second) || !lastBudgetLog.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("WAF inspection budget spent: a body waited too long",
		"method", method, "outcome", outcome, "client_ip", clientIPFrom(req),
		"budget_bytes", inspectBudget.Total(), "wait", budgetWait.String(),
		"refused_total", budgetRefused.Load(), "passed_total", budgetFailOpen.Load()+respmodOverBudget.Load())
}

// refuseOverBudget answers a request whose body did not get into the budget
// in time. It was not inspected, so it is refused with a 503, fail closed,
// unless WAF_FAIL_OPEN=1 chose availability over inspection.
func refuseOverBudget(w icap.ResponseWriter, req *icap.Request, eventID string) {
	if wafFailOpen {
		budgetFailOpen.Add(1)
		logOverBudget("REQMOD", "passed uninspected (WAF_FAIL_OPEN=1)", req)
		passThrough(w, req)
		return
	}
	budgetRefused.Add(1)
	logOverBudget("REQMOD", "refused with 503", req)
	body := `<html><body><h1>503 Service Unavailable</h1><p>The WAF is busy inspecting other requests. Try again shortly.</p></body></html>`
	resp := &http.Response{
		Status:        "503 Service Unavailable",
		StatusCode:    http.StatusServiceUnavailable,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Set("Retry-After", "10")
	if eventID != "" {
		resp.Header.Set("X-WAF-Event-Id", eventID)
	}
	w.WriteHeader(200, resp, true)
}

// respmodWeight is what EvaluateResponse reads: a text body that is not
// compressed. Other responses reserve nothing.
func respmodWeight(req *icap.Request) int64 {
	resp := req.Response
	ct := resp.Header.Get("Content-Type")
	if !engine.IsTextContent(ct) || engine.IsCompressedEncoding(resp.Header.Get("Content-Encoding")) {
		return 0
	}
	return bodyWeight(req.Header, resp.ContentLength, resp.Body)
}

// passOverBudget answers a response whose body did not get into the budget in
// time: the checks that need no body still run, then it passes, as a response
// does when the WAF cannot be reached (RESPMOD bypass=1).
func passOverBudget(w icap.ResponseWriter, req *icap.Request) {
	headersOnly := *req.Response
	headersOnly.Body = nil
	if v := inspect.EvaluateResponse(eng, &headersOnly); v.Blocked {
		blockResponse(w, req, v.Category, v.Score, v.Rules, "content_type", req.Response.Header.Get("Content-Type"))
		return
	}
	respmodOverBudget.Add(1)
	logOverBudget("RESPMOD", "passed uninspected", req)
	passThrough(w, req)
}

// writeBudgetMetrics exposes the budget on /metrics.
func writeBudgetMetrics(w io.Writer) {
	fmt.Fprintf(w, "# HELP waf_inspect_budget_bytes Body bytes the WAF inspects at the same time, at most.\n# TYPE waf_inspect_budget_bytes gauge\nwaf_inspect_budget_bytes %d\n", inspectBudget.Total())
	fmt.Fprintf(w, "# HELP waf_inspect_budget_used_bytes Body bytes reserved by inspections now.\n# TYPE waf_inspect_budget_used_bytes gauge\nwaf_inspect_budget_used_bytes %d\n", inspectBudget.Used())
	fmt.Fprintf(w, "# HELP waf_inspect_budget_waited_total Bodies that waited for the inspection budget.\n# TYPE waf_inspect_budget_waited_total counter\nwaf_inspect_budget_waited_total %d\n", budgetWaited.Load())
	fmt.Fprintf(w, "# HELP waf_inspect_budget_over_total Bodies that waited longer than the limit, by outcome.\n# TYPE waf_inspect_budget_over_total counter\n")
	fmt.Fprintf(w, "waf_inspect_budget_over_total{outcome=\"reqmod_refused\"} %d\n", budgetRefused.Load())
	fmt.Fprintf(w, "waf_inspect_budget_over_total{outcome=\"reqmod_fail_open\"} %d\n", budgetFailOpen.Load())
	fmt.Fprintf(w, "waf_inspect_budget_over_total{outcome=\"respmod_passed\"} %d\n", respmodOverBudget.Load())
}
