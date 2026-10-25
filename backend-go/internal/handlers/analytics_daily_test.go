package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type blockedByDayResp struct {
	Data struct {
		TZ   string `json:"tz"`
		Days []struct {
			Date    string        `json:"date"`
			Start   int64         `json:"start"`
			End     int64         `json:"end"`
			Blocked int           `json:"blocked"`
			Reasons []reasonCount `json:"reasons"`
		} `json:"days"`
		Reasons  []reasonCount `json:"reasons"`
		Internal *int          `json:"internal_sources"`
	} `json:"data"`
}

func withAnalyticsNow(t *testing.T, now time.Time) {
	t.Helper()
	prev := analyticsNow
	analyticsNow = func() time.Time { return now }
	t.Cleanup(func() { analyticsNow = prev })
}

func mustZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// The days are the viewer's calendar days: Rome left summer time at 03:00 on
// Sunday 25 October 2026, so that day has 25 hours, and a block ten minutes
// after midnight on the 26th is on the 26th, although it is still the 25th in
// UTC.
func TestBlockedByDayCountsTheViewersCalendarDays(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	rome := mustZone(t, "Europe/Rome")
	withAnalyticsNow(t, time.Date(2026, 10, 27, 12, 0, 0, 0, rome))
	at := func(d, h, m int) time.Time { return time.Date(2026, 10, d, h, m, 0, 0, rome) }

	insertLogRow(t, db, at(20, 23, 59), lanClient, "GET", "http://before.test/", 1, "waf")
	insertLogRow(t, db, at(25, 0, 30), lanClient, "GET", "http://a.test/", 1, "waf")
	insertLogRow(t, db, at(25, 23, 30), lanClient, "CONNECT", "b.test:443", 1, "ip_blacklist")
	insertLogRow(t, db, at(26, 0, 10), lanClient, "CONNECT", "c.test:443", 1, "domain_blacklist_dns")
	insertLogRow(t, db, at(27, 11, 0), lanClient, "CONNECT", "c.test:443", 1, "domain_blacklist_dns")
	insertLogRow(t, db, at(27, 11, 0), lanClient, "GET", "http://old.test/", 1, "unclassified")
	// Not counted: allowed, a sinkhole answer, the stack's own address.
	insertLogRow(t, db, at(27, 11, 0), lanClient, "GET", "http://ok.test/", 0, "none")
	insertLogRow(t, db, at(27, 11, 0), proxyClient, "DNS", "c.test", 1, "domain_blacklist_dns")
	insertLogRow(t, db, at(27, 11, 0), "127.0.0.1", "GET", "http://self.test/", 1, "waf")

	var resp blockedByDayResp
	getJSON(t, NewAnalyticsHandlers(db, cfg).BlockedByDay, "/api/analytics/blocked-by-day?tz=Europe/Rome", &resp)
	d := resp.Data
	if d.TZ != "Europe/Rome" {
		t.Errorf("tz = %q", d.TZ)
	}
	want := []struct {
		date    string
		blocked int
		reasons map[string]int
	}{
		{"2026-10-21", 0, nil}, {"2026-10-22", 0, nil}, {"2026-10-23", 0, nil}, {"2026-10-24", 0, nil},
		{"2026-10-25", 2, map[string]int{"waf": 1, "ip_blacklist": 1}},
		{"2026-10-26", 1, map[string]int{"domain_blacklist_dns": 1}},
		{"2026-10-27", 2, map[string]int{"domain_blacklist_dns": 1, "unclassified": 1}},
	}
	if len(d.Days) != len(want) {
		t.Fatalf("%d days, want %d: %+v", len(d.Days), len(want), d.Days)
	}
	for i, w := range want {
		got := d.Days[i]
		if got.Date != w.date || got.Blocked != w.blocked {
			t.Errorf("day %d = %s with %d blocked, want %s with %d", i, got.Date, got.Blocked, w.date, w.blocked)
		}
		if got.Reasons == nil {
			t.Errorf("%s: reasons is null, want a list", got.Date)
		}
		gr := countsByReason(got.Reasons)
		if len(gr) != len(w.reasons) {
			t.Errorf("%s: reasons %v, want %v", got.Date, gr, w.reasons)
		}
		for k, v := range w.reasons {
			if gr[k] != v {
				t.Errorf("%s: %s = %d, want %d", got.Date, k, gr[k], v)
			}
		}
		if i > 0 && got.Start != d.Days[i-1].End {
			t.Errorf("%s starts at %d, the day before ends at %d", got.Date, got.Start, d.Days[i-1].End)
		}
	}
	if h := d.Days[4].End - d.Days[4].Start; h != 25*3600 {
		t.Errorf("25 October lasts %d s, want 25 hours", h)
	}
	if h := d.Days[5].End - d.Days[5].Start; h != 24*3600 {
		t.Errorf("26 October lasts %d s, want 24 hours", h)
	}
	if d.Days[0].Start != at(21, 0, 0).Unix() || d.Days[6].End != time.Date(2026, 10, 28, 0, 0, 0, 0, rome).Unix() {
		t.Errorf("window %d to %d, want Rome midnights of 21 and 28 October", d.Days[0].Start, d.Days[6].End)
	}
	// Totals of the window, largest first, then by reason, with the labels.
	order := []string{"domain_blacklist_dns", "ip_blacklist", "unclassified", "waf"}
	if len(d.Reasons) != len(order) {
		t.Fatalf("reasons = %+v, want %v", d.Reasons, order)
	}
	for i, r := range d.Reasons {
		if r.Reason != order[i] || r.Label == "" {
			t.Errorf("reasons[%d] = %+v, want %s with a label", i, r, order[i])
		}
	}
	if d.Reasons[0].Count != 2 || d.Reasons[0].Label != "Domain blacklist (DNS)" {
		t.Errorf("reasons[0] = %+v, want 2 labelled Domain blacklist (DNS)", d.Reasons[0])
	}
	if d.Internal == nil || *d.Internal != 1 {
		t.Errorf("internal_sources = %v, want 1 (127.0.0.1)", d.Internal)
	}
}

// A zone with a 45-minute offset: the day starts at its own midnight.
func TestBlockedByDayFollowsAnyOffset(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	ktm := mustZone(t, "Asia/Kathmandu")
	withAnalyticsNow(t, time.Date(2026, 10, 25, 9, 0, 0, 0, ktm))
	insertLogRow(t, db, time.Date(2026, 10, 24, 23, 59, 0, 0, ktm), lanClient, "GET", "http://a.test/", 1, "waf")
	insertLogRow(t, db, time.Date(2026, 10, 25, 0, 1, 0, 0, ktm), lanClient, "GET", "http://a.test/", 1, "waf")
	var resp blockedByDayResp
	getJSON(t, NewAnalyticsHandlers(db, cfg).BlockedByDay, "/api/analytics/blocked-by-day?tz=Asia/Kathmandu", &resp)
	days := resp.Data.Days
	if len(days) != 7 || days[5].Date != "2026-10-24" || days[5].Blocked != 1 || days[6].Date != "2026-10-25" || days[6].Blocked != 1 {
		t.Errorf("days = %+v, want one block on 24 and one on 25 October", days)
	}
}

func TestBlockedByDayRejectsAZoneItCannotResolve(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg)
	for _, tz := range []string{"Mars/Olympus", "Local", "../../etc/passwd", "Europe/Rome%00"} {
		w := httptest.NewRecorder()
		h.BlockedByDay(w, httptest.NewRequest("GET", "/api/analytics/blocked-by-day?tz="+tz, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("tz=%s: status %d, want 400", tz, w.Code)
		}
	}
	var resp blockedByDayResp
	getJSON(t, h.BlockedByDay, "/api/analytics/blocked-by-day", &resp)
	if resp.Data.TZ != "UTC" || len(resp.Data.Days) != 7 {
		t.Errorf("no tz: %q with %d days, want UTC with 7", resp.Data.TZ, len(resp.Data.Days))
	}
}
