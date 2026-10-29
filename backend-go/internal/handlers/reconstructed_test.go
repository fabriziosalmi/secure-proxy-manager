package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// A client's requests the DNS sinkhole blocked before reasons were recorded
// (a /503 with blocked = 0) are, after the start-up reconstruction, counted
// as blocked in the client's drill-down: under their own reason and label in
// blocked_by_reason, and in the blocked count of their top destination.
func TestClientDetailsCountReconstructedSinkholeBlocks(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	const ip = "192.168.0.109"
	if _, err := db.Exec(`INSERT INTO domain_blacklist(domain, added_date) VALUES ('dpm.demdex.net', '2026-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	insert := func(dest, status string, n int) {
		for i := 0; i < n; i++ {
			if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, blocked, block_reason)
				VALUES ('2026-03-01 00:00:00', 1772323200, ?, 'CONNECT', ?, ?, 0, 'unclassified')`, ip, dest, status); err != nil {
				t.Fatal(err)
			}
		}
	}
	insert("dpm.demdex.net:443", "TCP_TUNNEL/503", 3)
	insert("dpm.demdex.net:443", "TCP_MISS_ABORTED/503", 1)
	insert("ok.example:443", "TCP_TUNNEL/200", 2)
	// Start the release that carries the step on a database from the one before.
	if _, err := db.Exec("PRAGMA user_version = 2"); err != nil {
		t.Fatal(err)
	}
	if err := database.Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}

	r := withChiParam(httptest.NewRequest("GET", "/api/clients/"+ip+"/details", nil), "ip", ip)
	w := httptest.NewRecorder()
	NewAnalyticsHandlers(db, cfg).ClientDetails(w, r)
	var resp struct {
		Data struct {
			Blocked    int           `json:"blocked"`
			ByReason   []reasonCount `json:"blocked_by_reason"`
			TopDomains []struct {
				Destination string `json:"destination"`
				Requests    int    `json:"requests"`
				Blocked     int    `json:"blocked"`
			} `json:"top_domains"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	want := reasonCount{Reason: "domain_blacklist_dns_reconstructed", Label: "Domain blacklist (DNS sinkhole), reconstructed", Count: 4}
	if len(resp.Data.ByReason) != 1 || resp.Data.ByReason[0] != want {
		t.Errorf("blocked_by_reason = %+v, want [%+v]", resp.Data.ByReason, want)
	}
	if resp.Data.Blocked != 4 {
		t.Errorf("blocked = %d, want 4", resp.Data.Blocked)
	}
	got := map[string][2]int{}
	for _, d := range resp.Data.TopDomains {
		got[d.Destination] = [2]int{d.Requests, d.Blocked}
	}
	if got["dpm.demdex.net"] != [2]int{4, 4} || got["ok.example"] != [2]int{2, 0} {
		t.Errorf("top_domains = %v, want dpm.demdex.net 4 requests 4 blocked, ok.example 2 requests 0 blocked", got)
	}
}
