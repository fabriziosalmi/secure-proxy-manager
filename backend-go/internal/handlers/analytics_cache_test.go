package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type cacheByDayResp struct {
	Data struct {
		TZ       string `json:"tz"`
		Outcomes []struct {
			Outcome string `json:"outcome"`
			Label   string `json:"label"`
		} `json:"outcomes"`
		Days []struct {
			Date     string           `json:"date"`
			Start    int64            `json:"start"`
			End      int64            `json:"end"`
			Requests map[string]int64 `json:"requests"`
			Bytes    map[string]int64 `json:"bytes"`
		} `json:"days"`
		Totals struct {
			Requests map[string]int64 `json:"requests"`
			Bytes    map[string]int64 `json:"bytes"`
		} `json:"totals"`
		Internal *int `json:"internal_sources"`
	} `json:"data"`
}

func insertStatusRow(t *testing.T, db *sql.DB, at time.Time, src, method, status string, bytes int64, blocked int) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, blocked, block_reason)
		VALUES(?, ?, ?, ?, 'http://a.test/', ?, ?, ?, 'none')`,
		at.UTC().Format("2006-01-02 15:04:05"), at.Unix(), src, method, status, bytes, blocked); err != nil {
		t.Fatal(err)
	}
}

// Every day has every outcome, zeros included; a row lands on the viewer's
// calendar day (Rome's 25 October 2026 has 25 hours); the classes are the
// ones the metrics use; DNS sinkhole rows and the stack's own requests are
// left out, as the blocked-by-day chart leaves them out.
func TestCacheByDayCountsRequestsAndBytesByOutcome(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	rome := mustZone(t, "Europe/Rome")
	withAnalyticsNow(t, time.Date(2026, 10, 27, 12, 0, 0, 0, rome))
	at := func(d, h, m int) time.Time { return time.Date(2026, 10, d, h, m, 0, 0, rome) }

	insertStatusRow(t, db, at(20, 23, 59), lanClient, "GET", "TCP_HIT/200", 999, 0) // before the window
	insertStatusRow(t, db, at(25, 0, 30), lanClient, "GET", "TCP_MEM_HIT/200", 100, 0)
	insertStatusRow(t, db, at(25, 23, 30), lanClient, "GET", "TCP_REFRESH_UNMODIFIED/200", 200, 0)
	insertStatusRow(t, db, at(26, 0, 10), lanClient, "GET", "TCP_MISS/200", 300, 0)
	insertStatusRow(t, db, at(26, 0, 20), lanClient, "GET", "TCP_MISS/200", 30, 0)
	insertStatusRow(t, db, at(27, 11, 0), lanClient, "CONNECT", "TCP_TUNNEL/200", 5000, 0)
	insertStatusRow(t, db, at(27, 11, 0), lanClient, "GET", "TCP_MISS/403", 10, 1)
	insertStatusRow(t, db, at(27, 11, 0), lanClient, "GET", "NONE_NONE/400", 4, 0)
	// Not counted: a sinkhole answer and the stack's own address.
	insertStatusRow(t, db, at(27, 11, 0), proxyClient, "DNS", "DNS_SINKHOLE/0", 0, 1)
	insertStatusRow(t, db, at(27, 11, 0), "127.0.0.1", "GET", "TCP_HIT/200", 777, 0)

	var resp cacheByDayResp
	getJSON(t, NewAnalyticsHandlers(db, cfg).CacheByDay, "/api/analytics/cache-by-day?tz=Europe/Rome", &resp)
	d := resp.Data
	if d.TZ != "Europe/Rome" {
		t.Errorf("tz = %q", d.TZ)
	}
	order := []string{"hit", "revalidated", "miss", "tunnel", "refused", "other"}
	if len(d.Outcomes) != len(order) {
		t.Fatalf("outcomes = %+v", d.Outcomes)
	}
	for i, o := range order {
		if d.Outcomes[i].Outcome != o || d.Outcomes[i].Label == "" {
			t.Errorf("outcome %d = %+v, want %q with a label", i, d.Outcomes[i], o)
		}
	}
	if len(d.Days) != 7 {
		t.Fatalf("%d days", len(d.Days))
	}
	want := map[string]struct{ req, bytes map[string]int64 }{
		"2026-10-25": {map[string]int64{"hit": 1, "revalidated": 1}, map[string]int64{"hit": 100, "revalidated": 200}},
		"2026-10-26": {map[string]int64{"miss": 2}, map[string]int64{"miss": 330}},
		"2026-10-27": {map[string]int64{"tunnel": 1, "refused": 1, "other": 1}, map[string]int64{"tunnel": 5000, "refused": 10, "other": 4}},
	}
	for _, day := range d.Days {
		if len(day.Requests) != len(order) || len(day.Bytes) != len(order) {
			t.Errorf("%s: not every outcome present: %+v %+v", day.Date, day.Requests, day.Bytes)
		}
		w := want[day.Date]
		for _, o := range order {
			if day.Requests[o] != w.req[o] {
				t.Errorf("%s requests[%s] = %d, want %d", day.Date, o, day.Requests[o], w.req[o])
			}
			if day.Bytes[o] != w.bytes[o] {
				t.Errorf("%s bytes[%s] = %d, want %d", day.Date, o, day.Bytes[o], w.bytes[o])
			}
		}
	}
	if d.Days[4].End-d.Days[4].Start != 25*3600 {
		t.Errorf("25 October is %d s long, want 25 h", d.Days[4].End-d.Days[4].Start)
	}
	if d.Totals.Requests["miss"] != 2 || d.Totals.Bytes["tunnel"] != 5000 || d.Totals.Requests["hit"] != 1 {
		t.Errorf("totals = %+v", d.Totals)
	}
	if d.Internal == nil {
		t.Error("internal_sources missing")
	}
}

func TestCacheByDayRefusesAZoneThatIsNotOne(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	w := httptest.NewRecorder()
	NewAnalyticsHandlers(db, cfg).CacheByDay(w, httptest.NewRequest("GET", "/api/analytics/cache-by-day?tz=Mars/Base", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
}

func TestCacheStoreReaderReadsTheProxysRecord(t *testing.T) {
	dir := t.TempDir()
	read := CacheStoreReader(dir)
	if _, ok := read(); ok {
		t.Error("no file must read as nothing, not zeros")
	}
	now := time.Now().Unix()
	rec := `{"version": 1, "collected_at": ` + strconv.FormatInt(now-30, 10) + `, "interval_s": 60, "disk_used_kb": 426420,
		"disk_capacity_kb": 1024000, "memory_used_kb": 240, "store_entries": 808}`
	if err := os.WriteFile(filepath.Join(dir, cacheStatsFile), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	s, ok := read()
	if !ok {
		t.Fatal("a current record must be read")
	}
	if s.AgeS < 29 || s.AgeS > 40 || *s.DiskUsedKB != 426420 || *s.DiskCapacityKB != 1024000 || *s.MemoryUsedKB != 240 || *s.Objects != 808 {
		t.Errorf("store = %+v", s)
	}
	if err := os.WriteFile(filepath.Join(dir, cacheStatsFile), []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := read(); ok {
		t.Error("an unreadable record must read as nothing")
	}
}
