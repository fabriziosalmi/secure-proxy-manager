package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appMW "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

// waf_status says why the dashboard has no WAF statistics. The field did not
// exist: waf was null with no reason, and the UI hid its WAF cards, so a WAF
// that refused the backend's credential looked like no WAF at all.
func TestDashboardSummaryReportsWhyWAFStatsAreMissing(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   string
	}{
		{"credential refused (403)", http.StatusForbidden, "auth_failed"},
		{"credential refused (401)", http.StatusUnauthorized, "auth_failed"},
		{"server error", http.StatusInternalServerError, "error"},
		{"ok", http.StatusOK, "ok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, _, cfg, cleanup := setupTestDB(t)
			defer cleanup()
			wafBreaker = appMW.NewCircuitBreaker(3, 30*time.Second)
			defer func() { wafBreaker = appMW.NewCircuitBreaker(3, 30*time.Second) }()

			var gotAuth string
			waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				w.WriteHeader(c.status)
				if c.status == http.StatusOK {
					_, _ = w.Write([]byte(`{"total_requests":1}`))
				}
			}))
			defer waf.Close()
			cfg.WAFURL = waf.URL
			cfg.AlertToken = "svc-token"

			w := httptest.NewRecorder()
			NewAnalyticsHandlers(db, cfg).DashboardSummary(w, httptest.NewRequest("GET", "/api/dashboard/summary", nil))
			var resp struct {
				Data map[string]any `json:"data"`
			}
			_ = json.NewDecoder(w.Body).Decode(&resp)
			if got := resp.Data["waf_status"]; got != c.want {
				t.Errorf("waf_status = %v, want %s", got, c.want)
			}
			if gotAuth != "Bearer svc-token" {
				t.Errorf("the backend sent Authorization %q, want the service token", gotAuth)
			}
		})
	}

	t.Run("unreachable", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		wafBreaker = appMW.NewCircuitBreaker(3, 30*time.Second)
		defer func() { wafBreaker = appMW.NewCircuitBreaker(3, 30*time.Second) }()
		cfg.WAFURL = "http://127.0.0.1:1"
		w := httptest.NewRecorder()
		NewAnalyticsHandlers(db, cfg).DashboardSummary(w, httptest.NewRequest("GET", "/api/dashboard/summary", nil))
		var resp struct {
			Data map[string]any `json:"data"`
		}
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if got := resp.Data["waf_status"]; got != "unreachable" {
			t.Errorf("waf_status = %v, want unreachable", got)
		}
	})
}
