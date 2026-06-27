package main

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// latencyHistogram is a lock-free, Prometheus-compatible histogram for the WAF
// hot path. The WAF deliberately avoids the prometheus client dependency and
// hand-rolls its exposition format, so this mirrors that style: atomic per-bucket
// counters plus a microsecond sum, rendered as cumulative *_bucket/_sum/_count
// lines. It exists because LatencyUS was previously computed but only written to
// the (often dead) JSONL — there was no way to derive p50/p95/p99.
type latencyHistogram struct {
	bounds   []float64      // upper bounds in seconds (ascending)
	counts   []atomic.Int64 // per-bucket counts; len = len(bounds)+1 (last is +Inf)
	sumMicro atomic.Int64
	count    atomic.Int64
}

func newLatencyHistogram(bounds []float64) *latencyHistogram {
	return &latencyHistogram{bounds: bounds, counts: make([]atomic.Int64, len(bounds)+1)}
}

// Observe records one duration.
func (h *latencyHistogram) Observe(d time.Duration) {
	sec := d.Seconds()
	h.count.Add(1)
	h.sumMicro.Add(d.Microseconds())
	for i, b := range h.bounds {
		if sec <= b {
			h.counts[i].Add(1)
			return
		}
	}
	h.counts[len(h.bounds)].Add(1) // +Inf overflow bucket
}

// write emits the histogram in Prometheus text format (cumulative buckets).
func (h *latencyHistogram) write(w io.Writer, name, help string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	cum := int64(0)
	for i, b := range h.bounds {
		cum += h.counts[i].Load()
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, b, cum)
	}
	cum += h.counts[len(h.bounds)].Load()
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, cum)
	fmt.Fprintf(w, "%s_sum %g\n", name, float64(h.sumMicro.Load())/1e6)
	fmt.Fprintf(w, "%s_count %d\n", name, h.count.Load())
}

// reqmodLatency tracks REQMOD inspection latency. Buckets span ~0.1ms..1s, the
// range a per-request regex/heuristic scan realistically falls in.
var reqmodLatency = newLatencyHistogram([]float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1,
})
