package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// exportBackup returns the body GET /api/maintenance/backup-config writes.
func exportBackup(t *testing.T, h *MaintenanceHandlers) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	h.BackupConfig(w, httptest.NewRequest("GET", "/api/maintenance/backup-config", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("backup: status %d", w.Code)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	return env.Data
}

func restoreBackup(t *testing.T, h *MaintenanceHandlers, body []byte) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	h.RestoreConfig(w, httptest.NewRequest("POST", "/api/maintenance/restore-config", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("restore: status %d: %s", w.Code, w.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

// entryScope is the scope of the source of a domain blacklist entry, "" when
// the entry is not stored.
func entryScope(t *testing.T, h *MaintenanceHandlers, domain string) string {
	t.Helper()
	var scope string
	err := h.db.QueryRow(`SELECT COALESCE(s.scope, 'global') FROM domain_blacklist d
		LEFT JOIN list_sources s ON s.id = d.source_id WHERE d.domain = ?`, domain).Scan(&scope)
	if err != nil {
		return ""
	}
	return scope
}

// A list that blocks only a group's clients must stay a group's list after a
// backup is restored, and the group must come back with its members, its
// schedule and its lists. Restore used to put every entry under one global
// "Restore" source and leave the groups out, so the group's blocks applied
// to every client.
func TestRestoreKeepsAGroupsOnlyListForItsGroup(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	src := NewMaintenanceHandlers(db, cfg)

	sid, err := database.NewSource(db, "domain_blacklist", database.SourcePaste, "kids")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domain_blacklist(domain, description, source_id) VALUES('games.example', 'kids only', ?)`, sid); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domain_blacklist(domain, description) VALUES('malware.example', 'everyone')`); err != nil {
		t.Fatal(err)
	}
	if err := database.SetSourceScope(db, "domain_blacklist", sid, database.ScopeGroups); err != nil {
		t.Fatal(err)
	}
	g := database.ClientGroup{
		Name: "Kids", Description: "the children's devices",
		Members:  []string{"192.168.1.50", "192.168.1.64/28"},
		Lists:    []int64{sid},
		Schedule: &database.GroupSchedule{Days: "MTWHF", Start: "15:00", End: "19:00"},
	}
	if err := database.SaveClientGroup(db, &g); err != nil {
		t.Fatal(err)
	}
	if got := entryScope(t, src, "games.example"); got != database.ScopeGroups {
		t.Fatalf("before the backup the entry is %q, want groups", got)
	}
	backup := exportBackup(t, src)

	db2, _, cfg2, cleanup2 := setupTestDB(t)
	defer cleanup2()
	dst := NewMaintenanceHandlers(db2, cfg2)
	restoreBackup(t, dst, backup)

	if got := entryScope(t, dst, "games.example"); got != database.ScopeGroups {
		t.Errorf("after the restore games.example is %q, want groups: it would block every client", got)
	}
	if got := entryScope(t, dst, "malware.example"); got != database.ScopeGlobal {
		t.Errorf("after the restore malware.example is %q, want global", got)
	}
	groups, err := database.ListClientGroups(db2)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("%d groups after the restore, want 1", len(groups))
	}
	r := groups[0]
	if r.Name != "Kids" || r.Description != "the children's devices" || r.Schedule == nil ||
		r.Schedule.Days != "MTWHF" || r.Schedule.Start != "15:00" || r.Schedule.End != "19:00" {
		t.Errorf("group = %+v", r)
	}
	if len(r.Members) != 2 || len(r.Lists) != 1 {
		t.Fatalf("members %v, lists %v", r.Members, r.Lists)
	}
	var list, scope string
	if err := db2.QueryRow("SELECT list, scope FROM list_sources WHERE id = ?", r.Lists[0]).Scan(&list, &scope); err != nil {
		t.Fatal(err)
	}
	if list != "domain_blacklist" || scope != database.ScopeGroups {
		t.Errorf("the group's list is %s/%s", list, scope)
	}
	var n int
	_ = db2.QueryRow("SELECT COUNT(*) FROM domain_blacklist WHERE source_id = ?", r.Lists[0]).Scan(&n)
	if n != 1 {
		t.Errorf("the group's list holds %d entries, want 1 (games.example)", n)
	}
}

// entrySources is the kind, label and scope of the source an entry was added by,
// and the kinds of its other sources.
func entrySources(t *testing.T, db *sql.DB, domain string) (kind, scope string, others []string) {
	t.Helper()
	if err := db.QueryRow(`SELECT s.kind, s.scope FROM domain_blacklist d JOIN list_sources s ON s.id = d.source_id
		WHERE d.domain = ?`, domain).Scan(&kind, &scope); err != nil {
		t.Fatalf("%s: %v", domain, err)
	}
	rows, err := db.Query(`SELECT s.kind || '/' || s.scope FROM domain_blacklist_sources x JOIN list_sources s ON s.id = x.source_id
		JOIN domain_blacklist d ON d.id = x.entry_id WHERE d.domain = ? ORDER BY 1`, domain)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var o string
		_ = rows.Scan(&o)
		others = append(others, o)
	}
	return kind, scope, others
}

func count(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A file exported before version 3 restores as it always did, under one
// Restore source, and the response says what it did not carry.
func TestRestoreOfAVersion2BackupSaysWhatItDidNotCarry(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)
	out := restoreBackup(t, h, []byte(`{"backup_version":2,"settings":{},"lists":{"domain_blacklist":[{"value":"old.example","description":"v2"}]}}`))
	if got, _ := json.Marshal(out["not_in_backup"]); string(got) != `["client_groups","list_sources","waf_policy"]` {
		t.Errorf("not_in_backup = %s", got)
	}
	if kind, scope, _ := entrySources(t, db, "old.example"); kind != database.SourceRestore || scope != database.ScopeGlobal {
		t.Errorf("old.example under %s/%s, want restore/global", kind, scope)
	}
	if out["waf_policy"] != nil {
		t.Errorf("waf_policy = %v, want null", out["waf_policy"])
	}
}

// Every source of an entry comes back: the URL list that added it and the
// pasted list that also lists it, each with its scope.
func TestRestoreKeepsEveryOtherSourceOfAnEntry(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	urlID, err := database.KeyedSource(db, "domain_blacklist", database.SourceURL, "https://lists.example/ads.txt", "Ads")
	if err != nil {
		t.Fatal(err)
	}
	pasteID, err := database.NewSource(db, "domain_blacklist", database.SourcePaste, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domain_blacklist(domain, description, source_id) VALUES('ads.example', '', ?)`, urlID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domain_blacklist(domain, description, source_id) VALUES('only-pasted.example', '', ?)`, pasteID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.LinkListed(db, "domain_blacklist", "ads.example", pasteID); err != nil {
		t.Fatal(err)
	}
	if err := database.SetSourceScope(db, "domain_blacklist", pasteID, database.ScopeGroups); err != nil {
		t.Fatal(err)
	}
	backup := exportBackup(t, NewMaintenanceHandlers(db, cfg))

	db2, _, cfg2, cleanup2 := setupTestDB(t)
	defer cleanup2()
	restoreBackup(t, NewMaintenanceHandlers(db2, cfg2), backup)
	kind, scope, others := entrySources(t, db2, "ads.example")
	if kind != database.SourceURL || scope != database.ScopeGlobal || len(others) != 1 || others[0] != "paste/groups" {
		t.Errorf("ads.example: %s/%s, others %v; want url/global and paste/groups", kind, scope, others)
	}
	var label string
	_ = db2.QueryRow(`SELECT label FROM list_sources WHERE kind = 'url' AND source = 'https://lists.example/ads.txt'`).Scan(&label)
	if label != "Ads" {
		t.Errorf("the URL source's label is %q", label)
	}
}

// An entry that a global source lists here stays global after a restore
// that has it in a group's list: the group's source is added as one of its
// other sources, which is how the export already treats an entry two scopes
// list (database/client_groups.go).
func TestRestoreOntoAnEntryListedGloballyKeepsItGlobal(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	sid, _ := database.NewSource(db, "domain_blacklist", database.SourcePaste, "kids")
	if _, err := db.Exec(`INSERT INTO domain_blacklist(domain, description, source_id) VALUES('games.example', '', ?)`, sid); err != nil {
		t.Fatal(err)
	}
	if err := database.SetSourceScope(db, "domain_blacklist", sid, database.ScopeGroups); err != nil {
		t.Fatal(err)
	}
	backup := exportBackup(t, NewMaintenanceHandlers(db, cfg))

	db2, _, cfg2, cleanup2 := setupTestDB(t)
	defer cleanup2()
	manual, _ := database.KeyedSource(db2, "domain_blacklist", database.SourceManual, "", "")
	if _, err := db2.Exec(`INSERT INTO domain_blacklist(domain, description, source_id) VALUES('games.example', 'by hand', ?)`, manual); err != nil {
		t.Fatal(err)
	}
	restoreBackup(t, NewMaintenanceHandlers(db2, cfg2), backup)
	kind, scope, others := entrySources(t, db2, "games.example")
	if kind != database.SourceManual || scope != database.ScopeGlobal || len(others) != 1 || others[0] != "paste/groups" {
		t.Errorf("games.example: %s/%s, others %v", kind, scope, others)
	}
}

// A group with the backup's name is replaced by the backup's; a group the
// groups API would refuse is skipped with its reason.
func TestRestoreReplacesAGroupOfTheSameNameAndSkipsAnInvalidOne(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)
	old := database.ClientGroup{Name: "Kids", Members: []string{"10.0.0.1"}, Lists: []int64{}}
	if err := database.SaveClientGroup(db, &old); err != nil {
		t.Fatal(err)
	}
	out := restoreBackup(t, h, []byte(`{"backup_version":3,"list_sources":[],"client_groups":[
		{"name":"Kids","description":"new","members":["192.168.1.50"],"lists":[],"schedule":null,"allowlist_only":true},
		{"name":"bad/name","description":"","members":["192.168.1.60"],"lists":[],"schedule":null,"allowlist_only":false},
		{"name":"Lost","description":"","members":["192.168.1.70"],"lists":[99],"schedule":null,"allowlist_only":false}]}`))
	groups, _ := database.ListClientGroups(db)
	if len(groups) != 1 || groups[0].Description != "new" || !groups[0].AllowlistOnly || len(groups[0].Members) != 1 || groups[0].Members[0] != "192.168.1.50/32" {
		t.Errorf("groups = %+v", groups)
	}
	if out["restored_groups"] != float64(1) {
		t.Errorf("restored_groups = %v", out["restored_groups"])
	}
	skipped, _ := out["skipped_groups"].([]any)
	if len(skipped) != 2 {
		t.Fatalf("skipped_groups = %v", out["skipped_groups"])
	}
	for _, s := range skipped {
		m := s.(map[string]any)
		if m["reason"] == "" {
			t.Errorf("%v has no reason", m)
		}
	}
}

// A URL source the list refresh would not fetch is not restored; its entries
// come back under the Restore source.
func TestRestoreRefusesASourceURLThatIsNotHTTP(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	out := restoreBackup(t, NewMaintenanceHandlers(db, cfg), []byte(`{"backup_version":3,
		"list_sources":[{"id":7,"list":"domain_blacklist","kind":"url","source":"file:///etc/passwd","label":"","scope":"global"}],
		"lists":{"domain_blacklist":[{"value":"x.example","description":"","source":7}]}}`))
	if n := count(t, db, `SELECT COUNT(*) FROM list_sources WHERE kind = 'url'`); n != 0 {
		t.Errorf("%d URL sources stored", n)
	}
	if kind, _, _ := entrySources(t, db, "x.example"); kind != database.SourceRestore {
		t.Errorf("x.example under %s, want restore", kind)
	}
	if skipped, _ := out["skipped_sources"].([]any); len(skipped) != 1 {
		t.Errorf("skipped_sources = %v", out["skipped_sources"])
	}
}

// Restoring the same backup twice changes nothing the second time: no second
// copy of a pasted list, no second group.
func TestRestoringTheSameBackupTwiceAddsNothing(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	sid, _ := database.NewSource(db, "domain_blacklist", database.SourcePaste, "")
	for _, d := range []string{"a.example", "b.example"} {
		if _, err := db.Exec(`INSERT INTO domain_blacklist(domain, description, source_id) VALUES(?, '', ?)`, d, sid); err != nil {
			t.Fatal(err)
		}
	}
	_ = database.SetSourceScope(db, "domain_blacklist", sid, database.ScopeGroups)
	g := database.ClientGroup{Name: "Kids", Members: []string{"192.168.1.50"}, Lists: []int64{sid}}
	if err := database.SaveClientGroup(db, &g); err != nil {
		t.Fatal(err)
	}
	h := NewMaintenanceHandlers(db, cfg)
	backup := exportBackup(t, h)
	snapshot := func() string {
		var s string
		_ = db.QueryRow(`SELECT (SELECT COUNT(*) FROM list_sources) || '/' || (SELECT COUNT(*) FROM domain_blacklist) || '/' ||
			(SELECT COUNT(*) FROM domain_blacklist_sources) || '/' || (SELECT COUNT(*) FROM client_groups) || '/' ||
			(SELECT COUNT(*) FROM client_group_lists)`).Scan(&s)
		return s
	}
	before := snapshot()
	restoreBackup(t, h, backup)
	restoreBackup(t, h, backup)
	if after := snapshot(); after != before {
		t.Errorf("sources/entries/links/groups/group lists: %s before, %s after two restores", before, after)
	}
}

// The WAF policy goes into the backup, and a restore writes it through the
// WAF's validation; a policy the WAF refuses is reported and not written,
// and the rest of the restore stands.
func TestBackupCarriesTheWAFPolicyAndRestoreWritesItThroughTheWAF(t *testing.T) {
	src := newPolicyFixture(t)
	policy := `{"version":1,"mode":"observe","exceptions":[{"rule":"SQLI-001","host":"app.example"}]}`
	if err := os.WriteFile(src.cfg.WAFPolicyFile, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	backup := exportBackup(t, NewMaintenanceHandlers(src.db, src.cfg))
	var env map[string]any
	_ = json.Unmarshal(backup, &env)
	if env["waf_policy"] == nil {
		t.Fatalf("the backup has no waf_policy: %s", backup)
	}

	dst := newPolicyFixture(t)
	out := restoreBackup(t, NewMaintenanceHandlers(dst.db, dst.cfg), backup)
	if wp, _ := out["waf_policy"].(map[string]any); wp["restored"] != true {
		t.Errorf("waf_policy = %v", out["waf_policy"])
	}
	var got, want wafPolicyFile
	_ = json.Unmarshal([]byte(dst.file(t)), &got)
	_ = json.Unmarshal([]byte(policy), &want)
	if !samePolicy(got, want) {
		t.Errorf("restored policy %s", dst.file(t))
	}
	if dst.waf.validates.Load() != 1 {
		t.Errorf("the WAF validated %d times, want 1", dst.waf.validates.Load())
	}

	refused := newPolicyFixture(t)
	bad := bytes.Replace(backup, []byte("SQLI-001"), []byte("REFUSED-001"), 1)
	bad = bytes.Replace(bad, []byte(`"client_groups":[]`), []byte(`"client_groups":[{"name":"Kept","description":"","members":["10.1.1.1"],"lists":[],"schedule":null,"allowlist_only":false}]`), 1)
	out = restoreBackup(t, NewMaintenanceHandlers(refused.db, refused.cfg), bad)
	if wp, _ := out["waf_policy"].(map[string]any); wp["restored"] != false || wp["detail"] == "" {
		t.Errorf("waf_policy = %v", out["waf_policy"])
	}
	if _, err := os.Stat(refused.cfg.WAFPolicyFile); err == nil {
		t.Error("a refused policy was written")
	}
	if groups, _ := database.ListClientGroups(refused.db); len(groups) != 1 {
		t.Errorf("the rest of the restore did not stand: %d groups", len(groups))
	}
}
