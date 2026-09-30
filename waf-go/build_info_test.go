package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// A running WAF must be able to say which commit it was built from.
func TestHealthAndMetricsReportTheBuildCommit(t *testing.T) {
	old := GitCommit
	GitCommit = "abc1234"
	t.Cleanup(func() { GitCommit = old })

	w := httptest.NewRecorder()
	(&MgmtHandlers{}).MetricsHandler(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), `waf_build_info{commit="abc1234"} 1`) {
		t.Errorf("metrics do not carry the build commit:\n%s", w.Body.String())
	}
}

func TestHealthReportsTheBuildCommit(t *testing.T) {
	old := GitCommit
	GitCommit = "abc1234"
	t.Cleanup(func() { GitCommit = old })
	if eng == nil {
		t.Skip("engine not initialised in this test binary")
	}
	w := httptest.NewRecorder()
	(&MgmtHandlers{}).HealthHandler(w, httptest.NewRequest("GET", "/health", nil))
	if !strings.Contains(w.Body.String(), `"commit":"abc1234"`) {
		t.Errorf("health does not carry the build commit: %s", w.Body.String())
	}
}
