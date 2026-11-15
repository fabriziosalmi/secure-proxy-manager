package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// The three retired statistics routes answer 410 and name the route that
// replaces them, which must itself be registered and answer 200.
func TestRetiredStatisticsNameTheirReplacement(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	r := chi.NewRouter()
	h := NewAnalyticsHandlers(db, cfg)
	h.Register(r, func(next http.Handler) http.Handler { return next })
	NewLogHandlers(db).Register(r, func(next http.Handler) http.Handler { return next })
	for gone, replacement := range map[string]string{
		"/api/traffic/statistics":    "/api/logs/timeline",
		"/api/domains/statistics":    "/api/analytics/top-destinations",
		"/api/analytics/top-domains": "/api/analytics/top-destinations",
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", gone, nil))
		if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "GET "+replacement) {
			t.Errorf("GET %s: %d %s, want 410 naming GET %s", gone, w.Code, w.Body.String(), replacement)
		}
		w = httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", replacement, nil))
		if w.Code != http.StatusOK {
			t.Errorf("the replacement GET %s answers %d", replacement, w.Code)
		}
	}
}
