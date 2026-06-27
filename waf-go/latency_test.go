package main

import (
	"strings"
	"testing"
	"time"
)

func TestLatencyHistogram(t *testing.T) {
	h := newLatencyHistogram([]float64{0.001, 0.01, 0.1})
	// 1ms → bucket le=0.001; 5ms → le=0.01; 500ms → +Inf
	h.Observe(1 * time.Millisecond)
	h.Observe(5 * time.Millisecond)
	h.Observe(500 * time.Millisecond)

	var b strings.Builder
	h.write(&b, "waf_test_duration_seconds", "test")
	out := b.String()

	// Cumulative buckets: le=0.001 →1, le=0.01 →2, le=0.1 →2, +Inf →3.
	for _, want := range []string{
		`waf_test_duration_seconds_bucket{le="0.001"} 1`,
		`waf_test_duration_seconds_bucket{le="0.01"} 2`,
		`waf_test_duration_seconds_bucket{le="0.1"} 2`,
		`waf_test_duration_seconds_bucket{le="+Inf"} 3`,
		`waf_test_duration_seconds_count 3`,
		"# TYPE waf_test_duration_seconds histogram",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
