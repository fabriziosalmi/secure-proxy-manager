package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every change to the blocked and allowed lists and to the egress allowlist
// writes an audit row. On a test deployment 640,929 domains were cleared and
// 71,140 imported, and the audit log recorded neither: it held only sign-ins,
// settings saves and reloads.

type auditRow struct {
	user, action, target, details string
}

// auditRows returns the rows written for action, oldest first.
func auditRows(t *testing.T, db *sql.DB, action string) []auditRow {
	t.Helper()
	rs, err := db.Query("SELECT COALESCE(username,''), action, COALESCE(target,''), COALESCE(details,'') FROM audit_log WHERE action = ? ORDER BY id", action)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []auditRow
	for rs.Next() {
		var r auditRow
		if err := rs.Scan(&r.user, &r.action, &r.target, &r.details); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// oneAuditRow is the single row written for action.
func oneAuditRow(t *testing.T, db *sql.DB, action string) auditRow {
	t.Helper()
	rows := auditRows(t, db, action)
	if len(rows) != 1 {
		t.Fatalf("%s: %d audit rows, want 1: %v", action, len(rows), rows)
	}
	if rows[0].user != "admin" {
		t.Errorf("%s: user %q, want admin", action, rows[0].user)
	}
	return rows[0]
}

// detailsOf decodes the JSON details of a row.
func detailsOf(t *testing.T, r auditRow) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.details), &m); err != nil {
		t.Fatalf("%s details %q: %v", r.action, r.details, err)
	}
	return m
}

func wantDetails(t *testing.T, r auditRow, want map[string]any) {
	t.Helper()
	got := detailsOf(t, r)
	for k, v := range want {
		if fmt.Sprint(got[k]) != fmt.Sprint(v) {
			t.Errorf("%s: details[%s] = %v, want %v (details %s)", r.action, k, got[k], v, r.details)
		}
	}
}

func idOf(t *testing.T, db *sql.DB, table, col, value string) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRow("SELECT id FROM "+table+" WHERE "+col+" = ?", value).Scan(&id); err != nil {
		t.Fatalf("%s %s: %v", table, value, err)
	}
	return id
}

func TestAddingAndRemovingAnEntryIsAuditedOnEveryList(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	for _, c := range []struct {
		path, field, value, table, col, list string
	}{
		{"ip-blacklist", "ip", "203.0.113.5", "ip_blacklist", "ip", "ip_blacklist"},
		{"domain-blacklist", "domain", "bad.example", "domain_blacklist", "domain", "domain_blacklist"},
		{"ip-whitelist", "ip", "198.51.100.7", "ip_whitelist", "ip", "ip_whitelist"},
		{"domain-whitelist", "domain", "good.example", "domain_whitelist", "domain", "domain_whitelist"},
		{"egress-allowlist", "entry", "api.example.org", "dst_allowlist", "entry", "egress_allowlist"},
	} {
		body := fmt.Sprintf(`{%q:%q,"description":"why"}`, c.field, c.value)
		if code, out := call(t, h, "POST", "/api/"+c.path, body); code != http.StatusOK {
			t.Fatalf("POST %s = %d %v", c.path, code, out)
		}
		add := oneAuditRow(t, db, "add_"+c.list)
		if add.target != c.value || add.details != "why" {
			t.Errorf("add_%s = %+v, want target %s and the note", c.list, add, c.value)
		}

		id := idOf(t, db, c.table, c.col, c.value)
		if code, out := call(t, h, "DELETE", fmt.Sprintf("/api/%s/%d", c.path, id), ""); code != http.StatusOK {
			t.Fatalf("DELETE %s = %d %v", c.path, code, out)
		}
		// The entry by name: "id=42" said nothing once the row was gone.
		if rm := oneAuditRow(t, db, "remove_"+c.list); rm.target != c.value {
			t.Errorf("remove_%s target = %q, want %q", c.list, rm.target, c.value)
		}
	}
}

func TestBulkDeleteAndClearAllAreAuditedWithTheCountRemoved(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		if code, _ := call(t, h, "POST", "/api/ip-blacklist", `{"ip":"`+ip+`"}`); code != http.StatusOK {
			t.Fatalf("add %s = %d", ip, code)
		}
	}
	ids := fmt.Sprintf("[%d,%d]", idOf(t, db, "ip_blacklist", "ip", "203.0.113.1"), idOf(t, db, "ip_blacklist", "ip", "203.0.113.2"))
	if code, out := call(t, h, "POST", "/api/ip-blacklist/bulk-delete", `{"ids":`+ids+`}`); code != http.StatusOK {
		t.Fatalf("bulk delete = %d %v", code, out)
	}
	wantDetails(t, oneAuditRow(t, db, "bulk_remove_ip_blacklist"), map[string]any{"removed": 2})

	for _, d := range []string{"a.example", "b.example", "c.example", "d.example"} {
		if code, _ := call(t, h, "POST", "/api/domain-blacklist", `{"domain":"`+d+`"}`); code != http.StatusOK {
			t.Fatalf("add %s = %d", d, code)
		}
	}
	if code, out := call(t, h, "DELETE", "/api/domain-blacklist/clear-all", ""); code != http.StatusOK {
		t.Fatalf("clear-all = %d %v", code, out)
	}
	wantDetails(t, oneAuditRow(t, db, "clear_domain_blacklist"), map[string]any{"removed": 4})

	if code, _ := call(t, h, "POST", "/api/egress-allowlist", `{"entry":"api.example.org"}`); code != http.StatusOK {
		t.Fatal("egress add failed")
	}
	if code, _ := call(t, h, "DELETE", "/api/egress-allowlist/clear-all", ""); code != http.StatusOK {
		t.Fatal("egress clear-all failed")
	}
	wantDetails(t, oneAuditRow(t, db, "clear_egress_allowlist"), map[string]any{"removed": 1})
}

func TestImportsAreAuditedWithTheirSourceAndCounts(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	const url = "https://lists.example/hosts"
	// A feed's access key in the URL, as abuse.ch asks for one, stays out of
	// the log: it is exported to CSV and kept for a year.
	const keyed = "https://reader:hunter2@feeds.example/list.txt?auth-key=s3cr3t&format=hosts"
	serveImports(t, map[string]string{
		url:   "0.0.0.0 ads.example\n0.0.0.0 track.example\nnot a domain\n",
		keyed: "198.51.100.9\n10.0.0.0/8\n",
	})
	h := listRouter(t, db, cfg)

	if code, out := call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","url":"`+url+`","name":"StevenBlack Unified"}`); code != http.StatusOK {
		t.Fatalf("URL import = %d %v", code, out)
	}
	r := oneAuditRow(t, db, "import_domain_blacklist")
	if r.target != url {
		t.Errorf("import target = %q, want the URL", r.target)
	}
	wantDetails(t, r, map[string]any{"added": 2, "skipped": 1, "from": "url", "name": "StevenBlack Unified"})

	if code, _ := call(t, h, "POST", "/api/blacklists/import", `{"type":"ip","content":"203.0.113.40\n203.0.113.41"}`); code != http.StatusOK {
		t.Fatal("paste import failed")
	}
	p := oneAuditRow(t, db, "import_ip_blacklist")
	if p.target != "" {
		t.Errorf("paste import target = %q, want none", p.target)
	}
	wantDetails(t, p, map[string]any{"added": 2, "skipped": 0, "from": "paste"})

	if code, out := call(t, h, "POST", "/api/blacklists/import", `{"type":"ip","url":"`+keyed+`"}`); code != http.StatusOK {
		t.Fatalf("keyed import = %d %v", code, out)
	}
	k := auditRows(t, db, "import_ip_blacklist")[1]
	if strings.Contains(k.target, "s3cr3t") || strings.Contains(k.target, "hunter2") || !strings.Contains(k.target, "feeds.example/list.txt") || !strings.Contains(k.target, "format=hosts") {
		t.Errorf("keyed import target = %q, want the URL without its credentials", k.target)
	}
	wantDetails(t, k, map[string]any{"added": 1, "bogon_skipped": 1})

	// A refused import changed nothing and writes nothing.
	if code, _ := call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","url":"https://not-served.example/x"}`); code == http.StatusOK {
		t.Fatal("an unserved URL imported")
	}
	if n := len(auditRows(t, db, "import_domain_blacklist")); n != 1 {
		t.Errorf("a refused import wrote a row: %d import rows, want 1", n)
	}
}

func TestGeoBlockIsAuditedWithTheCountries(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cc") == "it" {
			_, _ = w.Write([]byte("2.32.0.0/16\n5.88.0.0/14\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()
	cfg.GeoIPURL = ts.URL
	h := listRouter(t, db, cfg)
	if code, out := call(t, h, "POST", "/api/blacklists/import-geo", `{"countries":["it","xx"]}`); code != http.StatusOK {
		t.Fatalf("geo = %d %v", code, out)
	}
	r := oneAuditRow(t, db, "geo_block")
	if r.target != "IT,XX" {
		t.Errorf("geo target = %q, want IT,XX", r.target)
	}
	wantDetails(t, r, map[string]any{"added": 2, "countries": 1, "requested": 2, "failed": []any{"XX: no data"}})
}

func TestRemovingASourceIsAuditedWithItsNameAndCount(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	const url = "https://lists.example/hosts"
	serveImports(t, map[string]string{url: "0.0.0.0 ads.example\n0.0.0.0 track.example\n0.0.0.0 more.example\n"})
	h := listRouter(t, db, cfg)
	if code, _ := call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","url":"`+url+`","name":"StevenBlack Unified"}`); code != http.StatusOK {
		t.Fatal("import failed")
	}
	src := sourceOf(t, db, "domain_blacklist", "domain", "ads.example")
	if code, out := call(t, h, "DELETE", fmt.Sprintf("/api/domain-blacklist/sources/%d", src.id.Int64), ""); code != http.StatusOK {
		t.Fatalf("remove source = %d %v", code, out)
	}
	r := oneAuditRow(t, db, "remove_source_domain_blacklist")
	if r.target != url {
		t.Errorf("remove source target = %q, want the URL", r.target)
	}
	wantDetails(t, r, map[string]any{"removed": 3, "kind": "url", "name": "StevenBlack Unified"})
}

func TestRestoringListsIsAuditedPerList(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	if code, _ := call(t, h, "POST", "/api/domain-blacklist", `{"domain":"known.example"}`); code != http.StatusOK {
		t.Fatal("seed failed")
	}
	m := NewMaintenanceHandlers(db, cfg)
	b := `{"backup_version":2,"lists":{
		"domain_blacklist":[{"value":"known.example"},{"value":"new1.example"},{"value":"new2.example"},{"value":"bad domain"}],
		"ip_whitelist":[{"value":"192.0.2.44"}],
		"dst_allowlist":[{"value":"203.0.113.0/24"},{"value":"api.example.org"}]}}`
	w := httptest.NewRecorder()
	m.RestoreConfig(w, withUserContext(httptest.NewRequest("POST", "/api/maintenance/restore-config", strings.NewReader(b)), "admin"))
	if w.Code != http.StatusOK {
		t.Fatalf("restore = %d: %s", w.Code, w.Body.String())
	}
	// known.example was already listed: two are new, one is refused.
	wantDetails(t, oneAuditRow(t, db, "restore_domain_blacklist"), map[string]any{"added": 2, "skipped": 1})
	wantDetails(t, oneAuditRow(t, db, "restore_ip_whitelist"), map[string]any{"added": 1, "skipped": 0})
	wantDetails(t, oneAuditRow(t, db, "restore_egress_allowlist"), map[string]any{"added": 2, "skipped": 0})
}

func TestRedactURLKeepsTheAddressAndDropsCredentials(t *testing.T) {
	for in, want := range map[string]string{
		"https://lists.example/hosts":                         "https://lists.example/hosts",
		"https://u:p@lists.example/a.txt":                     "https://lists.example/a.txt",
		"https://lists.example/a.txt?token=abc&cc=it":         "https://lists.example/a.txt?cc=it&token=redacted",
		"https://lists.example/a.txt?Auth-Key=abc":            "https://lists.example/a.txt?Auth-Key=redacted",
		"https://lists.example/a.txt?format=hosts&apikey=zzz": "https://lists.example/a.txt?apikey=redacted&format=hosts",
	} {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}
