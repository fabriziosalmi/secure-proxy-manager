package workers

import (
	"database/sql"
	"testing"
	"time"
)

func auditRefresh(t *testing.T, db *sql.DB, user string, at time.Time) {
	t.Helper()
	if _, err := db.Exec("INSERT INTO audit_log (username, action, target, details, timestamp) VALUES (?, 'refresh_blacklists', '', '{}', ?)",
		user, at.UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
}

// A run is due an interval after the last one in the audit log, whatever
// the restarts: the loop used to wait a whole interval after each start, so
// a backend restarted daily with a 24-hour interval could put it off for
// ever.
func TestRefreshDue(t *testing.T) {
	now := time.Date(2026, 11, 3, 18, 30, 0, 0, time.UTC)
	day := 24 * time.Hour
	cases := []struct {
		name  string
		audit []struct {
			user string
			ago  time.Duration
		}
		started time.Duration // ago
		ranAt   time.Duration // ago, 0 for none
		want    time.Duration
	}{
		{name: "never ran: now", started: 10 * time.Minute, want: 0},
		{name: "never ran, just started: after the start delay", started: time.Minute, want: time.Minute},
		{name: "ran 25 h ago, restarted 10 min ago: now, not in 24 h", audit: []struct {
			user string
			ago  time.Duration
		}{{"system", 25 * time.Hour}}, started: 10 * time.Minute, want: 0},
		{name: "ran 25 h ago, restarted 30 s ago: after the start delay", audit: []struct {
			user string
			ago  time.Duration
		}{{"system", 25 * time.Hour}}, started: 30 * time.Second, want: 90 * time.Second},
		{name: "ran 23 h 50 min ago: in 10 min", audit: []struct {
			user string
			ago  time.Duration
		}{{"system", 23*time.Hour + 50*time.Minute}}, started: 10 * time.Minute, want: 10 * time.Minute},
		{name: "ran 1 h ago: wait, checked again in 30 min", audit: []struct {
			user string
			ago  time.Duration
		}{{"system", time.Hour}}, started: 10 * time.Minute, want: refreshRecheck},
		{name: "the latest of several rows counts", audit: []struct {
			user string
			ago  time.Duration
		}{{"system", 30 * time.Hour}, {"system", 23*time.Hour + 55*time.Minute}}, started: 10 * time.Minute, want: 5 * time.Minute},
		{name: "a row by an admin is not the worker's run", audit: []struct {
			user string
			ago  time.Duration
		}{{"admin", time.Hour}}, started: 10 * time.Minute, want: 0},
		{name: "no row but a run in this process: no tight loop", started: 2 * time.Hour, ranAt: time.Hour, want: refreshRecheck},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			for _, a := range c.audit {
				auditRefresh(t, db, a.user, now.Add(-a.ago))
			}
			var ranAt time.Time
			if c.ranAt > 0 {
				ranAt = now.Add(-c.ranAt)
			}
			if got := refreshDue(now, now.Add(-c.started), lastBlocklistRefresh(db), ranAt, day); got != c.want {
				t.Errorf("wait %v, want %v", got, c.want)
			}
		})
	}
}

// The egress provider worker reads its own audit rows, success or failure,
// and not the blocklists' or an admin's.
func TestLastAuditedEgress(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	at := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	for _, r := range []struct {
		user, action string
		at           time.Time
	}{
		{"system", "egress_provider_refreshed", at},
		{"system", "egress_provider_refresh_failed", at.Add(time.Hour)},
		{"system", "refresh_blacklists", at.Add(2 * time.Hour)},
		{"admin", "egress_provider_refreshed", at.Add(3 * time.Hour)},
	} {
		if _, err := db.Exec("INSERT INTO audit_log (username, action, target, details, timestamp) VALUES (?, ?, '', '{}', ?)",
			r.user, r.action, r.at.Format("2006-01-02 15:04:05")); err != nil {
			t.Fatal(err)
		}
	}
	if got := lastEgressRefresh(db); !got.Equal(at.Add(time.Hour)) {
		t.Errorf("last egress run %v, want %v", got, at.Add(time.Hour))
	}
}
