package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The timeline grouped by UTC hour, so in a zone with a half-hour offset
// every hour of the chart began at half past (12:30, 15:30 in Asia/Kolkata).
// With ?tz= the hours are the zone's: a request at 10:40 UTC is in the
// 16:00 hour of Kolkata (16:10 there) and in the 08:00 hour of St John's
// (08:10 there, UTC-02:30 in summer, UTC-03:30 in winter).
func TestTimelineCountsTheViewersHours(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	now := time.Now().UTC()
	// Two requests 20 minutes apart that share a Kolkata hour but not a UTC one:
	// hh:50 and the next hh:10 UTC are hh+6:20 and hh+6:40 in Kolkata.
	base := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.UTC).Add(-3 * time.Hour)
	for _, at := range []time.Time{base.Add(-10 * time.Minute), base.Add(10 * time.Minute)} {
		if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, blocked, block_reason)
			VALUES (?, ?, '198.51.100.7', 'GET', 'http://example.com/', 'TCP_MISS/200', 0, 'none')`,
			at.Format("2006-01-02 15:04:05"), at.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	h := NewLogHandlers(db)
	get := func(q string) (int, []map[string]any) {
		w := httptest.NewRecorder()
		h.Timeline(w, httptest.NewRequest("GET", "/api/logs/timeline"+q, nil))
		var resp struct {
			Data []map[string]any `json:"data"`
		}
		_ = json.NewDecoder(w.Body).Decode(&resp)
		return w.Code, resp.Data
	}

	for _, zone := range []string{"Asia/Kolkata", "America/St_Johns"} {
		loc, _ := time.LoadLocation(zone)
		_, data := get("?tz=" + zone)
		if len(data) != 1 {
			t.Fatalf("%s: %d hours, want the two requests in one hour of the zone: %v", zone, len(data), data)
		}
		start := time.Unix(int64(data[0]["start"].(float64)), 0).In(loc)
		if start.Minute() != 0 || data[0]["total"] != float64(2) {
			t.Errorf("%s: hour starts at %s with %v requests, want :00 local with 2", zone, start.Format("15:04"), data[0]["total"])
		}
		if want := start.Format("2006-01-02 15:00:00"); data[0]["time"] != want {
			t.Errorf("%s: time %v, want %s", zone, data[0]["time"], want)
		}
	}

	// Without tz, as before: UTC hours, the two requests in two of them.
	_, data := get("")
	if len(data) != 2 || data[0]["time"] != base.Add(-time.Hour).Format("2006-01-02 15:00:00") || data[1]["time"] != base.Format("2006-01-02 15:00:00") {
		t.Errorf("default: %v, want the UTC hours %s and %s", data, base.Add(-time.Hour).Format("15:04"), base.Format("15:04"))
	}
	if code, _ := get("?tz=Mars/Olympus"); code != http.StatusBadRequest {
		t.Errorf("tz=Mars/Olympus: status %d, want 400", code)
	}
}
