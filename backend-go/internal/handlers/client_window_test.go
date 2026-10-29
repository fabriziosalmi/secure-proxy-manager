package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// The client list counts the last 7 days and the detail it opens counted
// every request ever logged, so the two read different numbers for the same
// client once it had older rows. ?window=7d gives the list's window; the
// default and ?window=all keep every row; any other value is refused.
func TestClientDetailsCountTheWindowAsked(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	insert := func(ip string, age time.Duration, blocked int, n int) {
		at := time.Now().Add(-age)
		for i := 0; i < n; i++ {
			if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, blocked, block_reason)
				VALUES (?, ?, ?, 'CONNECT', 'example.com:443', 'TCP_TUNNEL/200', ?, ?)`,
				at.UTC().Format("2006-01-02 15:04:05"), at.Unix(), ip, blocked, map[int]string{0: "none", 1: "waf"}[blocked]); err != nil {
				t.Fatal(err)
			}
		}
	}
	// 198.51.100.7: 3 requests a day ago (1 blocked), 5 thirty days ago (2 blocked).
	insert("198.51.100.7", 24*time.Hour, 0, 2)
	insert("198.51.100.7", 24*time.Hour, 1, 1)
	insert("198.51.100.7", 30*24*time.Hour, 0, 3)
	insert("198.51.100.7", 30*24*time.Hour, 1, 2)

	rtr := chi.NewRouter()
	NewAnalyticsHandlers(db, cfg).Register(rtr, func(next http.Handler) http.Handler { return next })
	get := func(path string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		rtr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var body struct {
			Data map[string]any `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body.Data
	}
	check := func(name, path, window string, total, blocked float64) {
		t.Helper()
		code, d := get(path)
		if code != http.StatusOK {
			t.Fatalf("%s: status %d", name, code)
		}
		if d["window"] != window || d["total_requests"] != total || d["blocked"] != blocked {
			t.Errorf("%s: window %v, %v requests, %v blocked; want %s, %v, %v", name, d["window"], d["total_requests"], d["blocked"], window, total, blocked)
		}
		byReason, _ := d["blocked_by_reason"].([]any)
		if len(byReason) != 1 || byReason[0].(map[string]any)["count"] != blocked {
			t.Errorf("%s: blocked_by_reason = %v, want one rule counting %v", name, byReason, blocked)
		}
	}
	check("address, 7 days", "/api/clients/198.51.100.7/details?window=7d", "7d", 3, 1)
	check("address, all", "/api/clients/198.51.100.7/details?window=all", "all", 8, 3)
	check("address, default", "/api/clients/198.51.100.7/details", "all", 8, 3)

	setGDPRMode(t, db, true)
	check("network, 7 days", "/api/clients/198.51.100.0%2F24/details?window=7d", "7d", 3, 1)
	check("network, default", "/api/clients/198.51.100.0%2F24/details", "all", 8, 3)

	if code, _ := get("/api/clients/198.51.100.0%2F24/details?window=30d"); code != http.StatusBadRequest {
		t.Errorf("window=30d: status %d, want 400", code)
	}
}
