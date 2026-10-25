package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// listRouter registers the blacklist routes the way main.go does, with an
// authentication middleware that lets the test through as "admin".
func listRouter(t *testing.T, db *sql.DB, cfg *config.Config) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	asAdmin := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, withUserContext(req, "admin"))
		})
	}
	NewBlacklistHandlers(db, cfg).Register(r, asAdmin)
	return r
}

func call(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	var rdr *bytes.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	} else {
		rdr = bytes.NewReader(nil)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, rdr))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// serveImports replaces the URL fetch for the duration of a test, so an
// import can read a list without a public address.
func serveImports(t *testing.T, lists map[string]string) {
	t.Helper()
	orig := fetchImportURL
	fetchImportURL = func(u string) (string, int, string) {
		if body, ok := lists[u]; ok {
			return body, 0, ""
		}
		return "", http.StatusBadRequest, "failed to fetch URL: not served by the test"
	}
	t.Cleanup(func() { fetchImportURL = orig })
}

type entrySource struct {
	kind, source, label string
	id                  sql.NullInt64
}

func sourceOf(t *testing.T, db *sql.DB, table, col, value string) entrySource {
	t.Helper()
	var e entrySource
	var kind, source, label sql.NullString
	err := db.QueryRow("SELECT e.source_id, s.kind, s.source, s.label FROM "+table+" e LEFT JOIN list_sources s ON s.id = e.source_id WHERE e."+col+" = ?", value).
		Scan(&e.id, &kind, &source, &label)
	if err != nil {
		t.Fatalf("%s %q: %v", table, value, err)
	}
	e.kind, e.source, e.label = kind.String, source.String, label.String
	return e
}

func TestImportsRecordWhereTheirEntriesCameFrom(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	const url = "https://lists.example/hosts"
	serveImports(t, map[string]string{url: "0.0.0.0 ads.example\n0.0.0.0 track.example\n"})
	h := listRouter(t, db, cfg)

	code, _ := call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","url":"`+url+`","name":"StevenBlack Unified"}`)
	if code != http.StatusOK {
		t.Fatalf("URL import = %d", code)
	}
	first := sourceOf(t, db, "domain_blacklist", "domain", "ads.example")
	if first.kind != "url" || first.source != url || first.label != "StevenBlack Unified" {
		t.Errorf("URL import source = %+v, want the URL with the Popular list name", first)
	}

	// The same list again, grown: one source, not two.
	serveImports(t, map[string]string{url: "0.0.0.0 ads.example\n0.0.0.0 new.example\n"})
	if code, _ := call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","url":"`+url+`"}`); code != http.StatusOK {
		t.Fatalf("second URL import = %d", code)
	}
	if again := sourceOf(t, db, "domain_blacklist", "domain", "new.example"); again.id != first.id || again.label != "StevenBlack Unified" {
		t.Errorf("re-import source = %+v, want the first one (%d) with its name kept", again, first.id.Int64)
	}

	// Pasted text is its own source each time.
	if code, _ := call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","content":"pasted.example"}`); code != http.StatusOK {
		t.Fatal("paste import failed")
	}
	paste := sourceOf(t, db, "domain_blacklist", "domain", "pasted.example")
	if paste.kind != "paste" || paste.id == first.id {
		t.Errorf("paste source = %+v, want a new pasted-list source", paste)
	}
	// An entry listed by a later source stays with the one that added it.
	if code, _ := call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","content":"ads.example\nother.example"}`); code != http.StatusOK {
		t.Fatal("second paste failed")
	}
	if s := sourceOf(t, db, "domain_blacklist", "domain", "ads.example"); s.id != first.id {
		t.Errorf("ads.example moved to source %d, want it to stay with %d", s.id.Int64, first.id.Int64)
	}
	// A paste that adds nothing leaves no empty source behind.
	var before, after int
	_ = db.QueryRow("SELECT COUNT(*) FROM list_sources").Scan(&before)
	if code, _ := call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","content":"ads.example"}`); code != http.StatusOK {
		t.Fatal("duplicate paste failed")
	}
	_ = db.QueryRow("SELECT COUNT(*) FROM list_sources").Scan(&after)
	if after != before {
		t.Errorf("a paste of only known entries left %d new source rows", after-before)
	}

	// The list carries the source next to each entry.
	code, body := call(t, h, "GET", "/api/domain-blacklist?limit=50", "")
	if code != http.StatusOK {
		t.Fatalf("list = %d", code)
	}
	byName := map[string]map[string]any{}
	for _, row := range body["data"].([]any) {
		m := row.(map[string]any)
		byName[m["domain"].(string)] = m
	}
	if r := byName["ads.example"]; r["source_kind"] != "url" || r["source"] != url || r["source_label"] != "StevenBlack Unified" || r["description"] != "" {
		t.Errorf("listed ads.example = %v", r)
	}
	if r := byName["pasted.example"]; r["source_kind"] != "paste" {
		t.Errorf("listed pasted.example = %v", r)
	}
}

func TestHandAddedEntriesShareTheManualSourceOfTheirList(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	for _, c := range []struct{ path, body, table, col, value string }{
		{"/api/ip-blacklist", `{"ip":"203.0.113.5"}`, "ip_blacklist", "ip", "203.0.113.5"},
		{"/api/ip-blacklist", `{"ip":"203.0.113.6","description":"scanner"}`, "ip_blacklist", "ip", "203.0.113.6"},
		{"/api/domain-blacklist", `{"domain":"bad.example"}`, "domain_blacklist", "domain", "bad.example"},
		{"/api/ip-whitelist", `{"ip":"198.51.100.7"}`, "ip_whitelist", "ip", "198.51.100.7"},
		{"/api/domain-whitelist", `{"domain":"good.example"}`, "domain_whitelist", "domain", "good.example"},
	} {
		if code, body := call(t, h, "POST", c.path, c.body); code != http.StatusOK {
			t.Fatalf("POST %s = %d %v", c.path, code, body)
		}
		if s := sourceOf(t, db, c.table, c.col, c.value); s.kind != "manual" {
			t.Errorf("%s %s: source %+v, want manual", c.table, c.value, s)
		}
	}
	a := sourceOf(t, db, "ip_blacklist", "ip", "203.0.113.5")
	b := sourceOf(t, db, "ip_blacklist", "ip", "203.0.113.6")
	if a.id != b.id {
		t.Errorf("two hand-added IPs have sources %d and %d, want one", a.id.Int64, b.id.Int64)
	}
	var desc string
	_ = db.QueryRow("SELECT description FROM ip_blacklist WHERE ip='203.0.113.6'").Scan(&desc)
	if desc != "scanner" {
		t.Errorf("the typed description = %q, want it kept", desc)
	}
}

func TestGeoAndRestoreRecordTheirSource(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cc") == "it" {
			_, _ = w.Write([]byte("2.32.0.0/16\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()
	cfg.GeoIPURL = ts.URL
	h := listRouter(t, db, cfg)

	if code, body := call(t, h, "POST", "/api/blacklists/import-geo", `{"countries":["it"]}`); code != http.StatusOK {
		t.Fatalf("geo import = %d %v", code, body)
	}
	if s := sourceOf(t, db, "ip_blacklist", "ip", "2.32.0.0/16"); s.kind != "geo" || s.source != "IT" {
		t.Errorf("geo source = %+v, want geo IT", s)
	}

	m := NewMaintenanceHandlers(db, cfg)
	restore := func() {
		b := `{"backup_version":2,"lists":{"domain_blacklist":[{"value":"restored.example","description":"from backup"}],"ip_whitelist":[{"value":"192.0.2.44"}]}}`
		w := httptest.NewRecorder()
		m.RestoreConfig(w, httptest.NewRequest("POST", "/api/maintenance/restore-config", strings.NewReader(b)))
		if w.Code != http.StatusOK {
			t.Fatalf("restore = %d: %s", w.Code, w.Body.String())
		}
	}
	restore()
	if s := sourceOf(t, db, "domain_blacklist", "domain", "restored.example"); s.kind != "restore" {
		t.Errorf("restored domain source = %+v, want restore", s)
	}
	if s := sourceOf(t, db, "ip_whitelist", "ip", "192.0.2.44"); s.kind != "restore" {
		t.Errorf("restored IP source = %+v, want restore", s)
	}
	// The same backup again adds nothing, so it leaves no empty source.
	var before, after int
	_ = db.QueryRow("SELECT COUNT(*) FROM list_sources WHERE kind = 'restore'").Scan(&before)
	restore()
	_ = db.QueryRow("SELECT COUNT(*) FROM list_sources WHERE kind = 'restore'").Scan(&after)
	if before != 2 || after != 2 {
		t.Errorf("restore sources: %d after the first restore (want 2), %d after the second (want 2)", before, after)
	}
}

// startExporter runs the real exporter, so a list change goes through the
// same path it takes in production. Started after the test has seeded its
// lists and exported them itself (exportNow), it has no request queued: the
// only export it runs is one the step under test asks for. The caller defers
// the returned stop, after its database cleanup, so the exporter stops first.
func startExporter(db *sql.DB, dir string) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	workers.StartExporter(ctx, db, dir)
	return func() { cancel(); time.Sleep(50 * time.Millisecond) }
}

func exportNow(t *testing.T, db *sql.DB, dir string) {
	t.Helper()
	if err := database.ExportBlacklistsToFiles(db, dir); err != nil {
		t.Fatal(err)
	}
}

// waitFor polls a file until check passes, for at most 5 seconds.
func waitFor(t *testing.T, path string, check func(string) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		last = string(b)
		if err == nil && check(last) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: %s never satisfied the check; last content:\n%s", what, filepath.Base(path), last)
}

func TestRemovingASourceStopsTheProxyAndTheDNSEnforcingItsEntries(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)

	if code, _ := call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","content":"gone-a.example\ngone-b.example"}`); code != http.StatusOK {
		t.Fatal("paste failed")
	}
	if code, _ := call(t, h, "POST", "/api/domain-blacklist", `{"domain":"stays.example"}`); code != http.StatusOK {
		t.Fatal("manual add failed")
	}
	if code, _ := call(t, h, "POST", "/api/blacklists/import", `{"type":"ip","content":"203.0.113.77"}`); code != http.StatusOK {
		t.Fatal("IP paste failed")
	}
	hosts := filepath.Join(cfg.ConfigDir, "dnsmasq.d", "blocklist.hosts")
	squidDomains := filepath.Join(cfg.ConfigDir, "domain_blacklist.txt")
	squidIPs := filepath.Join(cfg.ConfigDir, "ip_blacklist.txt")
	exportNow(t, db, cfg.ConfigDir)
	waitFor(t, hosts, func(s string) bool {
		return strings.Contains(s, "gone-a.example") && strings.Contains(s, "stays.example")
	}, "before removal")
	waitFor(t, squidIPs, func(s string) bool { return strings.Contains(s, "203.0.113.77") }, "IP before removal")
	defer startExporter(db, cfg.ConfigDir)()

	paste := sourceOf(t, db, "domain_blacklist", "domain", "gone-a.example")
	code, body := call(t, h, "GET", "/api/domain-blacklist/sources", "")
	if code != http.StatusOK {
		t.Fatalf("sources = %d", code)
	}
	rows := body["data"].([]any)
	if len(rows) != 2 {
		t.Fatalf("sources = %v, want the paste and the manual source", rows)
	}

	// The confirmation names how many entries go; the response says how many did.
	code, body = call(t, h, "DELETE", "/api/domain-blacklist/sources/"+itoa(int(paste.id.Int64)), "")
	if code != http.StatusOK {
		t.Fatalf("remove = %d %v", code, body)
	}
	if removed := body["data"].(map[string]any)["removed"]; removed != float64(2) {
		t.Errorf("removed = %v, want 2", removed)
	}
	gone := func(s string) bool {
		return !strings.Contains(s, "gone-a.example") && !strings.Contains(s, "gone-b.example") && strings.Contains(s, "stays.example")
	}
	waitFor(t, hosts, gone, "DNS sinkhole after removal")
	waitFor(t, squidDomains, gone, "Squid domain list after removal")

	// The IP list is a different table: its entries were not touched.
	if b, _ := os.ReadFile(squidIPs); !strings.Contains(string(b), "203.0.113.77") {
		t.Error("removing a domain source dropped an IP entry")
	}
	// A source of another list is not found here.
	ipSrc := sourceOf(t, db, "ip_blacklist", "ip", "203.0.113.77")
	if code, _ := call(t, h, "DELETE", "/api/domain-blacklist/sources/"+itoa(int(ipSrc.id.Int64)), ""); code != http.StatusNotFound {
		t.Errorf("removing an IP source through the domain list = %d, want 404", code)
	}
	if code, _ := call(t, h, "DELETE", "/api/domain-blacklist/sources/abc", ""); code != http.StatusBadRequest {
		t.Errorf("a malformed id = %d, want 400", code)
	}
}

func TestRemovingTheUnrecordedEntriesLeavesTheRecordedOnes(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	// Entries from before provenance: source_id NULL.
	if _, err := db.Exec("INSERT INTO ip_blacklist(ip, description) VALUES('203.0.113.1','Imported on 2026-10-25'),('203.0.113.2','Imported on 2026-10-25')"); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, h, "POST", "/api/ip-blacklist", `{"ip":"203.0.113.3"}`); code != http.StatusOK {
		t.Fatal("manual add failed")
	}
	exportNow(t, db, cfg.ConfigDir)
	defer startExporter(db, cfg.ConfigDir)()
	_, body := call(t, h, "GET", "/api/ip-blacklist/sources", "")
	rows := body["data"].([]any)
	last := rows[len(rows)-1].(map[string]any)
	if last["id"] != nil || last["kind"] != "unrecorded" || last["entries"] != float64(2) {
		t.Errorf("unrecorded row = %v, want id null, kind unrecorded, 2 entries", last)
	}
	code, body := call(t, h, "DELETE", "/api/ip-blacklist/sources/unrecorded", "")
	if code != http.StatusOK || body["data"].(map[string]any)["removed"] != float64(2) {
		t.Fatalf("remove unrecorded = %d %v", code, body)
	}
	waitFor(t, filepath.Join(cfg.ConfigDir, "ip_blacklist.txt"), func(s string) bool {
		return s == "203.0.113.3\n"
	}, "Squid IP list after removing the unrecorded entries")
}

// The allowed lists are exported files too. Their add and delete handlers
// requested no export, so an allowed entry took effect at the next blacklist
// change, whenever that was.
func TestAllowedListChangesReachTheExportedFiles(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	if code, _ := call(t, h, "POST", "/api/domain-blacklist", `{"domain":"cdn.example"}`); code != http.StatusOK {
		t.Fatal("blacklist add failed")
	}
	exportNow(t, db, cfg.ConfigDir)
	hosts := filepath.Join(cfg.ConfigDir, "dnsmasq.d", "blocklist.hosts")
	waitFor(t, hosts, func(s string) bool { return strings.Contains(s, "cdn.example") }, "blocked before allowing")
	defer startExporter(db, cfg.ConfigDir)()

	if code, _ := call(t, h, "POST", "/api/domain-whitelist", `{"domain":"cdn.example"}`); code != http.StatusOK {
		t.Fatal("whitelist add failed")
	}
	waitFor(t, hosts, func(s string) bool { return !strings.Contains(s, "cdn.example") }, "DNS sinkhole after allowing")

	if code, _ := call(t, h, "POST", "/api/ip-whitelist", `{"ip":"198.51.100.20"}`); code != http.StatusOK {
		t.Fatal("IP whitelist add failed")
	}
	allowIPs := filepath.Join(cfg.ConfigDir, "ip_whitelist.txt")
	waitFor(t, allowIPs, func(s string) bool { return strings.Contains(s, "198.51.100.20") }, "Squid allowed IPs after adding")

	var id int
	_ = db.QueryRow("SELECT id FROM ip_whitelist WHERE ip = '198.51.100.20'").Scan(&id)
	if code, _ := call(t, h, "DELETE", "/api/ip-whitelist/"+itoa(id), ""); code != http.StatusOK {
		t.Fatal("IP whitelist delete failed")
	}
	waitFor(t, allowIPs, func(s string) bool { return !strings.Contains(s, "198.51.100.20") }, "Squid allowed IPs after removing")
}

func TestEnforcementReportsOnlyWhatIsRecorded(t *testing.T) {
	t.Setenv("SPM_DNS_BLOCKLIST_MAX_DOMAINS", "5000")
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	for _, s := range []string{
		"INSERT INTO domain_blacklist(domain) VALUES('a.example'),('b.example'),('c.example')",
		"INSERT INTO domain_whitelist(domain) VALUES('b.example'),('unrelated.example')",
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	code, body := call(t, h, "GET", "/api/blacklists/enforcement", "")
	if code != http.StatusOK {
		t.Fatalf("enforcement = %d", code)
	}
	d := body["data"].(map[string]any)
	if d["dns_blocklist_limit"] != float64(5000) || d["domain_blacklist_entries"] != float64(3) || d["domain_blacklist_on_allowed"] != float64(1) {
		t.Errorf("enforcement = %v, want limit 5000, 3 entries, 1 of them allowed", d)
	}
	for _, k := range []string{"squid_domain_acl", "squid_ip_blacklist", "squid_ip_whitelist"} {
		if v, present := d[k]; !present || v != nil {
			t.Errorf("%s = %v, want null with no proxy record", k, v)
		}
	}

	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(cfg.ConfigDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ip_blacklist_acl_status.json", `{"version":1,"entries":50772,"networks":32215,"dropped":0,"written_at":1792900000}`+"\n")
	write("ip_whitelist_acl_status.json", `{"version":2,"entries":1,"networks":1,"dropped":0}`)
	write("domain_acl_status.json", `{"version":1,"names":473936,"limit":250000,"held":false,"written_at":1}`)
	_, body = call(t, h, "GET", "/api/blacklists/enforcement", "")
	d = body["data"].(map[string]any)
	ip, _ := d["squid_ip_blacklist"].(map[string]any)
	if ip == nil || ip["entries"] != float64(50772) || ip["networks"] != float64(32215) || ip["written_at"] != float64(1792900000) {
		t.Errorf("squid_ip_blacklist = %v", d["squid_ip_blacklist"])
	}
	if d["squid_ip_whitelist"] != nil {
		t.Errorf("a record of an unknown version was reported: %v", d["squid_ip_whitelist"])
	}
	if acl, _ := d["squid_domain_acl"].(map[string]any); acl == nil || acl["held"] != false || acl["names"] != float64(473936) {
		t.Errorf("squid_domain_acl = %v", d["squid_domain_acl"])
	}
}

// The proxy writes these records and the backend reads them: a rename on one
// side would turn every count into "not reported" with no test failing.
func TestTheProxyWritesTheRecordsTheBackendReads(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "proxy", "blacklist_watchdog.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{domainACLStatusFile, "ip_blacklist_acl_status.json", "ip_whitelist_acl_status.json"} {
		if !strings.Contains(string(src), `{CONFIG_DIR}/`+name+`"`) {
			t.Errorf("blacklist_watchdog.py does not write /config/%s", name)
		}
	}
}

func TestExportDownloadsTheWholeListNotOnePage(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	tx, _ := db.Begin()
	for i := 0; i < 1200; i++ { // more than the list endpoint's 1000-row page
		if _, err := tx.Exec("INSERT INTO ip_blacklist(ip) VALUES(?)", "203.0."+itoa(i/256)+"."+itoa(i%256)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/ip-blacklist/export", nil))
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("export = %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	lines := strings.Split(strings.TrimSuffix(w.Body.String(), "\n"), "\n")
	if len(lines) != 1200 || lines[0] != "203.0.0.0" || lines[1199] != "203.0.4.175" {
		t.Errorf("export has %d lines (first %q, last %q), want 1200 in the order added", len(lines), lines[0], lines[len(lines)-1])
	}
}

// Reset empties the lists before their sources, so the foreign key never
// refuses it and no source outlives its entries.
func TestResetEmptiesTheSourcesWithTheLists(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	if code, _ := call(t, h, "POST", "/api/blacklists/import", `{"type":"ip","content":"203.0.113.9"}`); code != http.StatusOK {
		t.Fatal("paste failed")
	}
	w := httptest.NewRecorder()
	NewDatabaseHandlers(db).Reset(w, withUserContext(httptest.NewRequest("POST", "/api/database/reset", nil), "admin"))
	var entries, sources int
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&entries)
	_ = db.QueryRow("SELECT COUNT(*) FROM list_sources").Scan(&sources)
	if entries != 0 || sources != 0 {
		t.Errorf("after reset: %d entries, %d sources; want none", entries, sources)
	}
}
