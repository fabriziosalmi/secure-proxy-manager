package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"secure-proxy-waf/internal/engine"
)

// captureLog routes the structured logger into a buffer for the test, as JSON
// lines, and restores the previous default afterwards.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestParseBlockThreshold(t *testing.T) {
	for raw, want := range map[string]int{"10": 10, " 15 ": 15, "1": 1} {
		if got, err := parseBlockThreshold(raw); err != nil || got != want {
			t.Errorf("parseBlockThreshold(%q) = %d, %v; want %d", raw, got, err, want)
		}
	}
	for _, raw := range []string{"5o", "0", "-3", "1.5", "ten", "0x10"} {
		if _, err := parseBlockThreshold(raw); err == nil {
			t.Errorf("parseBlockThreshold(%q) accepted", raw)
		}
	}
}

// A threshold set to make the WAF stricter and dropped without a word is the
// failure this guards: the operator must be told the value was rejected, and
// which one is in force.
func TestRejectedBlockThresholdIsLoggedAndTheDefaultKept(t *testing.T) {
	for _, bad := range []string{"5o", "0", "-3"} {
		t.Setenv("WAF_BLOCK_THRESHOLD", bad)
		buf := captureLog(t)
		cfg := engineConfigFromEnv()
		if cfg.BlockThreshold != 0 {
			t.Errorf("%q: threshold set to %d, want the default to stay in force", bad, cfg.BlockThreshold)
		}
		out := buf.String()
		if !strings.Contains(out, "WAF_BLOCK_THRESHOLD") || !strings.Contains(out, bad) ||
			!strings.Contains(out, "10") {
			t.Errorf("%q: log does not name the variable, the value and the threshold in use: %q", bad, out)
		}
	}

	t.Setenv("WAF_BLOCK_THRESHOLD", "7")
	buf := captureLog(t)
	if got := engineConfigFromEnv().BlockThreshold; got != 7 {
		t.Errorf("valid threshold = %d, want 7", got)
	}
	if strings.Contains(buf.String(), "rejected") {
		t.Errorf("a valid threshold was reported as rejected: %q", buf.String())
	}
	_ = engine.DefaultBlockThreshold
}
