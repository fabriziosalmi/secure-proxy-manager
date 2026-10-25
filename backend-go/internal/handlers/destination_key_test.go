package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func withChiParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// Squid logs a CONNECT as "host:443" and the DNS sinkhole logs the same site
// as "host", so the top lists showed evil.example:443 and evil.example as two
// destinations, each with part of the count. A :443 or :80 suffix is dropped
// for the grouping; any other port stays visible, because it is a different
// service.
func seedSplitDestinations(t *testing.T, insert func(dest string, n int)) {
	t.Helper()
	insert("evil.example:443", 3)   // Squid CONNECT
	insert("evil.example", 2)       // DNS sinkhole
	insert("plain.example:80", 1)   // Squid, explicit port 80
	insert("plain.example", 1)      // DNS sinkhole
	insert("other.example:8443", 4) // a different service: keeps its port
	insert("other.example", 1)
}

func TestDashboardSummaryTopBlockedGroupsDefaultPorts(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	seedSplitDestinations(t, func(dest string, n int) {
		for i := 0; i < n; i++ {
			if _, err := db.Exec(`INSERT INTO proxy_logs (timestamp, unix_timestamp, source_ip, destination, status, blocked)
				VALUES (datetime('now'), strftime('%s','now'), '192.168.0.109', ?, 'TCP_DENIED/403', 1)`, dest); err != nil {
				t.Fatal(err)
			}
		}
	})

	w := httptest.NewRecorder()
	NewAnalyticsHandlers(db, cfg).DashboardSummary(w, httptest.NewRequest("GET", "/api/dashboard/summary", nil))
	var resp struct {
		Data struct {
			TopBlocked []struct {
				Dest  string `json:"dest"`
				Count int    `json:"count"`
			} `json:"top_blocked"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, e := range resp.Data.TopBlocked {
		got[e.Dest] = e.Count
	}
	want := map[string]int{"evil.example": 5, "plain.example": 2, "other.example:8443": 4, "other.example": 1}
	if len(got) != len(want) {
		t.Fatalf("top_blocked = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("top_blocked[%q] = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
	// Ordered by the grouped count, so the merged destination ranks first.
	if len(resp.Data.TopBlocked) > 0 && resp.Data.TopBlocked[0].Dest != "evil.example" {
		t.Errorf("first entry = %q, want evil.example", resp.Data.TopBlocked[0].Dest)
	}
}

func TestClientDetailsTopDomainsGroupsDefaultPorts(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	seedSplitDestinations(t, func(dest string, n int) {
		for i := 0; i < n; i++ {
			if _, err := db.Exec(`INSERT INTO proxy_logs (timestamp, unix_timestamp, source_ip, destination, status, blocked)
				VALUES (datetime('now'), strftime('%s','now'), '192.168.0.109', ?, 'TCP_DENIED/403', ?)`, dest, i%2); err != nil {
				t.Fatal(err)
			}
		}
	})

	r := withChiParam(httptest.NewRequest("GET", "/api/clients/192.168.0.109/details", nil), "ip", "192.168.0.109")
	w := httptest.NewRecorder()
	NewAnalyticsHandlers(db, cfg).ClientDetails(w, r)
	var resp struct {
		Data struct {
			TopDomains []struct {
				Destination string `json:"destination"`
				Requests    int    `json:"requests"`
				Blocked     int    `json:"blocked"`
			} `json:"top_domains"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	got := map[string][2]int{}
	for _, e := range resp.Data.TopDomains {
		got[e.Destination] = [2]int{e.Requests, e.Blocked}
	}
	// blocked alternates 0,1 per inserted row: 3 rows -> 1 blocked, 2 -> 1, 1 -> 0, 4 -> 2.
	want := map[string][2]int{"evil.example": {5, 2}, "plain.example": {2, 0}, "other.example:8443": {4, 2}, "other.example": {1, 0}}
	if len(got) != len(want) {
		t.Fatalf("top_domains = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("top_domains[%q] = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
}
