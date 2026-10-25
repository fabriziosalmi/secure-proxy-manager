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
