package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	appMW "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

// snapRouter is the settings, groups, allowlist and snapshot routes, signed
// in as admin, with the snapshot middleware on.
func snapRouter(t *testing.T, db *sql.DB, cfg *config.Config) chi.Router {
	t.Helper()
	r := chi.NewRouter()
	signedIn := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), appMW.CtxUsername, "admin")))
		})
	}
	NewSnapshotHandlers(db, cfg).Register(r, signedIn)
	NewSettingsHandlers(db, cfg).Register(r, signedIn)
	NewBlacklistHandlers(db, cfg).Register(r, signedIn)
	t.Cleanup(func() { snapshotState.Store(nil) })
	return r
}

func snapCall(t *testing.T, r http.Handler, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, &buf))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func snapshotCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM config_snapshots").Scan(&n)
	return n
}

func settingValue(t *testing.T, db *sql.DB, k string) string {
	t.Helper()
	var v string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name = ?", k).Scan(&v)
	return v
}

// A save is preceded by a snapshot of the configuration it changes; a save
// that leaves the configuration as the newest snapshot has it adds none.
func TestASaveIsPrecededByASnapshot(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	r := snapRouter(t, db, cfg)
	if code, out := snapCall(t, r, "POST", "/api/settings", map[string]string{"log_retention_days": "45"}); code != http.StatusOK {
		t.Fatalf("save: %d %v", code, out)
	}
	if n := snapshotCount(t, db); n != 1 {
		t.Fatalf("%d snapshots after one save, want 1", n)
	}
	var reason, data string
	_ = db.QueryRow("SELECT reason, data FROM config_snapshots").Scan(&reason, &data)
	var s configSnapshot
	_ = json.Unmarshal([]byte(data), &s)
	if reason != "before a settings save" || s.Settings["log_retention_days"] == "45" {
		t.Errorf("snapshot %q holds log_retention_days=%q, want the value before the save", reason, s.Settings["log_retention_days"])
	}
	snapCall(t, r, "POST", "/api/settings", map[string]string{"log_retention_days": "45"})
	snapCall(t, r, "POST", "/api/settings", map[string]string{"log_retention_days": "45"})
	if n := snapshotCount(t, db); n != 2 {
		t.Errorf("%d snapshots, want 2: the second save changed the configuration, the third did not", n)
	}
}

// Restoring a snapshot makes the configuration its own exactly: a setting
// changed since goes back, a group added since goes, a group removed since
// comes back with its list, an allowlist entry added since goes. The
// restore takes a snapshot first, and restoring that one undoes it.
func TestRestoringASnapshotGivesBackThatConfiguration(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	r := snapRouter(t, db, cfg)
	sid, _ := database.NewSource(db, "domain_blacklist", database.SourcePaste, "kids")
	if _, err := db.Exec(`INSERT INTO domain_blacklist(domain, description, source_id) VALUES('games.example','',?)`, sid); err != nil {
		t.Fatal(err)
	}
	_ = database.SetSourceScope(db, "domain_blacklist", sid, database.ScopeGroups)
	kids := database.ClientGroup{Name: "Kids", Members: []string{"192.168.1.50"}, Lists: []int64{sid}}
	_ = database.NormalizeClientGroup(&kids) // as the groups API saves it
	if err := database.SaveClientGroup(db, &kids); err != nil {
		t.Fatal(err)
	}
	snapCall(t, r, "POST", "/api/settings", map[string]string{"log_retention_days": "30", "webhook_url": "https://hooks.example/a"})
	code, out := snapCall(t, r, "POST", "/api/config/snapshots", map[string]string{"note": "known good"})
	if code != http.StatusOK {
		t.Fatalf("take: %d %v", code, out)
	}
	good := int64(out["data"].(map[string]any)["id"].(float64))

	// Changes after the known good state.
	snapCall(t, r, "POST", "/api/settings", map[string]string{"log_retention_days": "7", "webhook_url": "https://hooks.example/b"})
	if _, err := database.DeleteClientGroup(db, kids.ID); err != nil {
		t.Fatal(err)
	}
	guests := database.ClientGroup{Name: "Guests", Members: []string{"192.168.2.0/24"}, Lists: []int64{}}
	_ = database.NormalizeClientGroup(&guests)
	_ = database.SaveClientGroup(db, &guests)
	if code, out := snapCall(t, r, "POST", "/api/egress-allowlist", map[string]string{"entry": "api.example.com"}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("allowlist add: %d %v", code, out)
	}

	code, out = snapCall(t, r, "GET", "/api/config/snapshots/"+strconv.FormatInt(good, 10)+"/diff", nil)
	if code != http.StatusOK {
		t.Fatalf("diff: %d %v", code, out)
	}
	d := out["data"].(map[string]any)
	b, _ := json.Marshal(d)
	for _, want := range []string{`"groups_added":["Kids"]`, `"groups_removed":["Guests"]`, `"egress_allowlist_removed":["api.example.com"]`,
		`{"from":"7","key":"log_retention_days","to":"30"}`, `{"from":null,"key":"webhook_url","secret":true,"to":null}`} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("diff lacks %s: %s", want, b)
		}
	}
	if bytes.Contains(b, []byte("hooks.example")) {
		t.Errorf("the diff shows a secret: %s", b)
	}

	code, out = snapCall(t, r, "POST", "/api/config/snapshots/"+strconv.FormatInt(good, 10)+"/restore", nil)
	if code != http.StatusOK {
		t.Fatalf("restore: %d %v", code, out)
	}
	undo := int64(out["data"].(map[string]any)["undo_snapshot"].(float64))
	if v := settingValue(t, db, "log_retention_days"); v != "30" {
		t.Errorf("log_retention_days = %q, want 30", v)
	}
	groups, _ := database.ListClientGroups(db)
	if len(groups) != 1 || groups[0].Name != "Kids" || len(groups[0].Lists) != 1 || groups[0].Lists[0] != sid {
		t.Errorf("groups = %+v", groups)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM dst_allowlist WHERE entry = 'api.example.com'`).Scan(&n)
	if n != 0 {
		t.Error("the allowlist entry added since is still there")
	}
	code, out = snapCall(t, r, "GET", "/api/config/snapshots/"+strconv.FormatInt(good, 10)+"/diff", nil)
	if same, _ := out["data"].(map[string]any)["same"].(bool); code != http.StatusOK || !same {
		t.Errorf("after the restore the diff is not empty: %v", out)
	}

	// Undo.
	if code, out := snapCall(t, r, "POST", "/api/config/snapshots/"+strconv.FormatInt(undo, 10)+"/restore", nil); code != http.StatusOK {
		t.Fatalf("undo: %d %v", code, out)
	}
	if v := settingValue(t, db, "log_retention_days"); v != "7" {
		t.Errorf("after the undo log_retention_days = %q, want 7", v)
	}
	groups, _ = database.ListClientGroups(db)
	if len(groups) != 1 || groups[0].Name != "Guests" {
		t.Errorf("after the undo groups = %+v", groups)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM dst_allowlist WHERE entry = 'api.example.com'`).Scan(&n)
	if n != 1 {
		t.Error("after the undo the allowlist entry is missing")
	}
	code, out = snapCall(t, r, "GET", "/api/config/snapshots", nil)
	// The newest snapshot is the state before the undo; the undo restored
	// snapshot undo, which is the one that holds the configuration now.
	list, _ := out["data"].([]any)
	current := []float64{}
	for _, it := range list {
		if m := it.(map[string]any); m["current"] == true {
			current = append(current, m["id"].(float64))
		}
	}
	if code != http.StatusOK || len(current) != 1 || int64(current[0]) != undo {
		t.Errorf("current snapshots %v, want [%d]: %v", current, undo, out)
	}
}

// A group whose list has been removed since comes back without it, and the
// response names it.
func TestARestoredGroupWhoseListIsGoneIsNamed(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	r := snapRouter(t, db, cfg)
	sid, _ := database.NewSource(db, "domain_blacklist", database.SourcePaste, "kids")
	if _, err := db.Exec(`INSERT INTO domain_blacklist(domain, description, source_id) VALUES('games.example','',?)`, sid); err != nil {
		t.Fatal(err)
	}
	_ = database.SetSourceScope(db, "domain_blacklist", sid, database.ScopeGroups)
	g := database.ClientGroup{Name: "Kids", Members: []string{"192.168.1.50"}, Lists: []int64{sid}}
	_ = database.SaveClientGroup(db, &g)
	_, out := snapCall(t, r, "POST", "/api/config/snapshots", nil)
	id := int64(out["data"].(map[string]any)["id"].(float64))
	_, _ = database.DeleteClientGroup(db, g.ID)
	if _, _, err := database.RemoveSource(db, "domain_blacklist", sid); err != nil {
		t.Fatal(err)
	}
	code, out := snapCall(t, r, "POST", "/api/config/snapshots/"+strconv.FormatInt(id, 10)+"/restore", nil)
	if code != http.StatusOK {
		t.Fatalf("restore: %d %v", code, out)
	}
	skipped, _ := out["data"].(map[string]any)["skipped_groups"].([]any)
	if len(skipped) != 1 {
		t.Errorf("skipped_groups = %v", out["data"])
	}
	groups, _ := database.ListClientGroups(db)
	if len(groups) != 1 || len(groups[0].Lists) != 0 {
		t.Errorf("groups = %+v", groups)
	}
}

// The WAF policy in a snapshot goes back through the WAF's check.
func TestASnapshotRestoresTheWAFPolicyThroughTheWAF(t *testing.T) {
	f := newPolicyFixture(t)
	r := snapRouter(t, f.db, f.cfg)
	if err := os.WriteFile(f.cfg.WAFPolicyFile, []byte(`{"version":1,"mode":"observe"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, out := snapCall(t, r, "POST", "/api/config/snapshots", nil)
	id := int64(out["data"].(map[string]any)["id"].(float64))
	if err := os.WriteFile(f.cfg.WAFPolicyFile, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := snapCall(t, r, "POST", "/api/config/snapshots/"+strconv.FormatInt(id, 10)+"/restore", nil)
	if code != http.StatusOK {
		t.Fatalf("restore: %d %v", code, out)
	}
	if wp, _ := out["data"].(map[string]any)["waf_policy"].(map[string]any); wp["restored"] != true {
		t.Errorf("waf_policy = %v", out["data"])
	}
	var got wafPolicyFile
	_ = json.Unmarshal([]byte(f.file(t)), &got)
	if modeOf(got) != "observe" || f.waf.validates.Load() != 1 {
		t.Errorf("policy mode %q, WAF validations %d", modeOf(got), f.waf.validates.Load())
	}
}

func TestSnapshotsAreKeptUpToTheLimit(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	for i := 0; i < snapshotKeep+5; i++ {
		if _, err := db.Exec("INSERT INTO config_snapshots(created_at, username, reason, sha256, data) VALUES(1,'','old',?,'{}')", strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := takeSnapshot(db, cfg, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if n := snapshotCount(t, db); n != snapshotKeep {
		t.Errorf("%d snapshots kept, want %d", n, snapshotKeep)
	}
	var newest string
	_ = db.QueryRow("SELECT reason FROM config_snapshots ORDER BY id DESC LIMIT 1").Scan(&newest)
	if newest != "test" {
		t.Errorf("the newest snapshot is %q", newest)
	}
}

func TestAnUnknownSnapshotIs404(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	r := snapRouter(t, db, cfg)
	for _, p := range []string{"/api/config/snapshots/999/diff", "/api/config/snapshots/abc/diff"} {
		if code, _ := snapCall(t, r, "GET", p, nil); code != http.StatusNotFound {
			t.Errorf("%s: %d", p, code)
		}
	}
	if code, _ := snapCall(t, r, "POST", "/api/config/snapshots/999/restore", nil); code != http.StatusNotFound {
		t.Errorf("restore 999: %d", code)
	}
}
