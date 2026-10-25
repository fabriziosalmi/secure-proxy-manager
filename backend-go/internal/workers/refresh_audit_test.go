package workers

import (
	"encoding/json"
	"errors"
	"testing"
)

// The auto-refresh worker adds entries to the blocked lists every run. It
// used to leave no trace in the audit log; each run now writes exactly one
// row, as the user "system", with what it did to each list.
func TestARefreshRunWritesOneAuditRowAsSystem(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	feeds := map[string]string{
		defaultIPLists[0]:     "1.1.1.1\n2.2.2.2\n10.0.0.1\n",
		defaultDomainLists[0]: "0.0.0.0 a.example\n0.0.0.0 b.example\n0.0.0.0 c.example\n",
	}
	orig := fetchRefreshFeed
	fetchRefreshFeed = func(u string) (string, error) {
		if body, ok := feeds[u]; ok {
			return body, nil
		}
		return "", errors.New("HTTP 410")
	}
	t.Cleanup(func() { fetchRefreshFeed = orig })

	type row struct {
		user, action, target, details string
	}
	rows := func() []row {
		t.Helper()
		rs, err := db.Query("SELECT COALESCE(username,''), action, COALESCE(target,''), COALESCE(details,'') FROM audit_log ORDER BY id")
		if err != nil {
			t.Fatal(err)
		}
		defer rs.Close()
		var out []row
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.user, &r.action, &r.target, &r.details); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	counts := func(details string) map[string]refreshCount {
		t.Helper()
		var c map[string]refreshCount
		if err := json.Unmarshal([]byte(details), &c); err != nil {
			t.Fatalf("details %q: %v", details, err)
		}
		return c
	}

	runRefresh(db)
	got := rows()
	if len(got) != 1 {
		t.Fatalf("one run wrote %d audit rows, want 1: %v", len(got), got)
	}
	if got[0].user != "system" || got[0].action != "refresh_blacklists" {
		t.Errorf("row = %+v, want system refresh_blacklists", got[0])
	}
	c := counts(got[0].details)
	// 10.0.0.1 is a LAN range and never enters the source IP blacklist; the
	// second feed of each list answers an error.
	if want := (refreshCount{Added: 2, Fetched: 1, Failed: 1}); c["ip_blacklist"] != want {
		t.Errorf("ip_blacklist = %+v, want %+v", c["ip_blacklist"], want)
	}
	if want := (refreshCount{Added: 3, Fetched: 1, Failed: 1}); c["domain_blacklist"] != want {
		t.Errorf("domain_blacklist = %+v, want %+v", c["domain_blacklist"], want)
	}

	// A second run finds nothing new, and says so in its own row.
	runRefresh(db)
	got = rows()
	if len(got) != 2 {
		t.Fatalf("two runs wrote %d audit rows, want 2", len(got))
	}
	c = counts(got[1].details)
	if c["ip_blacklist"].Added != 0 || c["domain_blacklist"].Added != 0 {
		t.Errorf("second run = %+v, want nothing added", c)
	}
}
