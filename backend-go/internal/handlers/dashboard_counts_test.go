package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type summaryCounts struct {
	Data struct {
		Total        int `json:"total_requests"`
		Blocked      int `json:"blocked_requests"`
		Today        int `json:"today_requests"`
		TodayBlocked int `json:"today_blocked"`
	} `json:"data"`
}

func insertLogRow(t *testing.T, db *sql.DB, at time.Time, src, method, dest string, blocked int, reason string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, blocked, block_reason)
		VALUES(?, ?, ?, ?, ?, 'TCP_MISS/200', 0, ?, ?)`,
		at.UTC().Format("2006-01-02 15:04:05"), at.Unix(), src, method, dest, blocked, reason); err != nil {
		t.Fatal(err)
	}
}

// The test deployment showed TODAY 1,235 next to TOTAL (all time) 1,234: the
// all-time count was cached for 25 seconds while today was read on every
// poll, so every request logged in between was in today and not in all time.
func TestDashboardTodayNeverExceedsAllTime(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	seedBlockReasonFixture(t, db) // 18 client requests, 13 blocked, 18 DNS rows, all now
	insertLogRow(t, db, time.Now().Add(-72*time.Hour), lanClient, "GET", "http://old.test/", 0, "none")
	h := NewAnalyticsHandlers(db, cfg)

	var first summaryCounts
	getJSON(t, h.DashboardSummary, "/api/dashboard/summary", &first)
	if first.Data.Total != 19 || first.Data.Today != 18 {
		t.Fatalf("before: total %d, today %d; want 19 and 18", first.Data.Total, first.Data.Today)
	}

	// Traffic logged within the cache window: 5 client requests (2 blocked)
	// and the DNS rows of their lookups, which are not requests.
	now := time.Now()
	for i := 0; i < 5; i++ {
		blocked, reason := 0, "none"
		if i < 2 {
			blocked, reason = 1, "domain_blacklist"
		}
		insertLogRow(t, db, now, lanClient, "GET", "http://new.test/", blocked, reason)
		insertLogRow(t, db, now, proxyClient, "DNS", "new.test", 0, "none")
	}

	var second summaryCounts
	getJSON(t, h.DashboardSummary, "/api/dashboard/summary", &second)
	d := second.Data
	if d.Today > d.Total || d.TodayBlocked > d.Blocked {
		t.Errorf("today %d (blocked %d) exceeds all time %d (blocked %d)", d.Today, d.TodayBlocked, d.Total, d.Blocked)
	}
	if d.Total != 24 || d.Today != 23 || d.Blocked != 15 || d.TodayBlocked != 15 {
		t.Errorf("after: total %d, today %d, blocked %d, today blocked %d; want 24, 23, 15, 15",
			d.Total, d.Today, d.Blocked, d.TodayBlocked)
	}
}

// A reset clears the logs; the all-time count must not keep the cleared rows.
func TestResetCountersClearsTheCachedAllTimeCount(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	seedBlockReasonFixture(t, db)
	cfg.WAFURL = "http://127.0.0.1:1" // nothing listens: the WAF reset fails fast
	h := NewAnalyticsHandlers(db, cfg)

	var before summaryCounts
	getJSON(t, h.DashboardSummary, "/api/dashboard/summary", &before)
	if before.Data.Total != 18 {
		t.Fatalf("before reset: total %d, want 18", before.Data.Total)
	}
	w := httptest.NewRecorder()
	h.ResetCounters(w, httptest.NewRequest("POST", "/api/counters/reset", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("reset: status %d", w.Code)
	}
	insertLogRow(t, db, time.Now(), lanClient, "GET", "http://after.test/", 0, "none")

	var after summaryCounts
	getJSON(t, h.DashboardSummary, "/api/dashboard/summary", &after)
	if after.Data.Total != 1 || after.Data.Today != 1 {
		t.Errorf("after reset: total %d, today %d; want 1 and 1", after.Data.Total, after.Data.Today)
	}
}

// The Overview shows the last 24 hours: requests, blocked, distinct clients,
// the rules that blocked them and, per destination, which rule did.
func TestDashboardReportsTheLast24Hours(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	seedBlockReasonFixture(t, db) // 18 client requests from lanClient, 13 blocked; 18 DNS rows
	now := time.Now()
	// Outside the window: a blocked request from another client 30 hours ago.
	insertLogRow(t, db, now.Add(-30*time.Hour), "192.168.0.50", "GET", "http://ip.test/", 1, "ip_blacklist")
	// Inside: a second client, and Squid's own ACL denying a sinkholed name.
	insertLogRow(t, db, now, "192.168.0.20", "GET", "http://pub.test/", 0, "none")
	insertLogRow(t, db, now, lanClient, "CONNECT", "sink.test:443", 1, "domain_blacklist")
	h := NewAnalyticsHandlers(db, cfg)

	var resp struct {
		Data struct {
			Requests    int             `json:"last_24h_requests"`
			Blocked     int             `json:"last_24h_blocked"`
			Clients     int             `json:"last_24h_clients"`
			LastRequest *string         `json:"last_request_at"`
			ByReason24h []reasonCount   `json:"blocked_by_reason_24h"`
			ByReason7d  []reasonCount   `json:"blocked_by_reason"`
			TopBlocked  []topBlockedRow `json:"top_blocked"`
			Recent      []struct {
				Destination string `json:"destination"`
				Host        string `json:"host"`
				Reason      string `json:"reason"`
				Label       string `json:"reason_label"`
			} `json:"recent_blocks"`
		} `json:"data"`
	}
	getJSON(t, h.DashboardSummary, "/api/dashboard/summary", &resp)
	d := resp.Data

	// 18 + 2 client requests; 13 + 1 blocked; lanClient and .20 (the proxy's
	// DNS rows are not a client, .50 is outside the window).
	if d.Requests != 20 || d.Blocked != 14 || d.Clients != 2 {
		t.Errorf("last 24h: %d requests, %d blocked, %d clients; want 20, 14, 2", d.Requests, d.Blocked, d.Clients)
	}
	if d.LastRequest == nil || *d.LastRequest == "" {
		t.Error("last_request_at is missing")
	}
	got24 := countsByReason(d.ByReason24h)
	want24 := map[string]int{"domain_blacklist_dns": 9, "domain_blacklist": 3, "waf": 1, "unclassified": 1}
	if len(got24) != len(want24) {
		t.Errorf("blocked_by_reason_24h = %v, want %v", got24, want24)
	}
	for k, v := range want24 {
		if got24[k] != v {
			t.Errorf("blocked_by_reason_24h[%s] = %d, want %d", k, got24[k], v)
		}
	}
	if countsByReason(d.ByReason7d)["ip_blacklist"] != 1 {
		t.Errorf("blocked_by_reason (7 days) lost the request from 30 hours ago: %v", countsByReason(d.ByReason7d))
	}

	// sink.test: 9 at the sinkhole, 1 by Squid's ACL, one row with both rules.
	var sink *topBlockedRow
	for i := range d.TopBlocked {
		if d.TopBlocked[i].Dest == "sink.test" {
			sink = &d.TopBlocked[i]
		}
	}
	if sink == nil {
		t.Fatalf("top_blocked misses sink.test: %+v", d.TopBlocked)
	}
	if sink.Count != 10 || len(sink.Reasons) != 2 ||
		sink.Reasons[0].Reason != "domain_blacklist_dns" || sink.Reasons[0].Count != 9 || sink.Reasons[0].Label != "Domain blacklist (DNS)" ||
		sink.Reasons[1].Reason != "domain_blacklist" || sink.Reasons[1].Count != 1 {
		t.Errorf("top_blocked sink.test = %+v; want 10 blocked, 9 domain_blacklist_dns then 1 domain_blacklist", *sink)
	}
	if d.TopBlocked[0].Dest != "sink.test" {
		t.Errorf("first top_blocked = %q, want sink.test", d.TopBlocked[0].Dest)
	}

	// The newest block is the ACL deny of sink.test:443.
	if len(d.Recent) == 0 {
		t.Fatal("recent_blocks is empty")
	}
	r := d.Recent[0]
	if r.Destination != "sink.test:443" || r.Host != "sink.test" || r.Reason != "domain_blacklist" || r.Label != "Domain blacklist" {
		t.Errorf("recent_blocks[0] = %+v", r)
	}
	for _, r := range d.Recent {
		if r.Label == "" || (r.Label == "WAF") != (r.Reason == "waf") {
			t.Errorf("recent block %q (%s) is labelled %q", r.Destination, r.Reason, r.Label)
		}
	}
}

type topBlockedRow struct {
	Dest    string        `json:"dest"`
	Count   int           `json:"count"`
	Reasons []reasonCount `json:"reasons"`
}
