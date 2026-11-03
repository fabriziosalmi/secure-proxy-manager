package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The most requested hosts of the window: one row per host whatever its port
// or path, with its blocked count, the stack's own traffic and older rows
// left out.
func TestTopDestinationsCountsHostsOfTheClients(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	now := time.Now()
	for _, r := range []struct {
		src, dest string
		blocked   int
		at        time.Time
	}{
		{lanClient, "a.test:443", 0, now},
		{lanClient, "a.test:443", 1, now},
		{lanClient, "http://a.test/x", 0, now},
		{lan172, "https://a.test/y", 0, now},
		{lanClient, "b.test:443", 0, now},
		{lanClient, "b.test:443", 0, now},
		// The backend's own requests and an 8-day-old one are not counted.
		{backendIP, "c.test:443", 0, now}, {backendIP, "c.test:443", 0, now}, {backendIP, "c.test:443", 0, now},
		{backendIP, "c.test:443", 0, now}, {backendIP, "c.test:443", 0, now},
		{lanClient, "old.test:443", 0, now.Add(-8 * 24 * time.Hour)},
	} {
		insertLogRow(t, db, r.at, r.src, "CONNECT", r.dest, r.blocked, "none")
	}
	h := NewAnalyticsHandlers(db, cfg).WithSources(composeSources(t, db))
	w := httptest.NewRecorder()
	h.TopDestinations(w, httptest.NewRequest("GET", "/api/analytics/top-destinations", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Data []struct {
			Host     string `json:"host"`
			Requests int    `json:"requests"`
			Blocked  int    `json:"blocked"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 2 || body.Data[0].Host != "a.test" || body.Data[0].Requests != 4 || body.Data[0].Blocked != 1 ||
		body.Data[1].Host != "b.test" || body.Data[1].Requests != 2 || body.Data[1].Blocked != 0 {
		t.Errorf("top destinations = %+v; want a.test 4 (1 blocked), b.test 2", body.Data)
	}
}
