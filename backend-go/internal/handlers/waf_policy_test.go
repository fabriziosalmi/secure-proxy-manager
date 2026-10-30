package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	appMW "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/privacy"
)

// fakeWAF answers the WAF's policy endpoints: /policy/validate refuses a
// policy that names the rule REFUSED-001, /policy reports the digest of the
// file on disk, and the reloads are counted.
type fakeWAF struct {
	srv       *httptest.Server
	path      string
	validates atomic.Int32
	reloads   atomic.Int32
}

func newFakeWAF(t *testing.T, path string) *fakeWAF {
	f := &fakeWAF{path: path}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/policy/validate":
			f.validates.Add(1)
			b, _ := io.ReadAll(r.Body)
			if bytes.Contains(b, []byte("REFUSED-001")) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"status":"error","detail":"exception 1: unknown rule \"REFUSED-001\""}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"ok","data":{}}`))
		case "/policy/reload":
			f.reloads.Add(1)
			_, _ = w.Write([]byte(`{"status":"ok","changed":true,"data":{}}`))
		case "/policy":
			digest := "empty"
			if b, err := os.ReadFile(f.path); err == nil {
				s := sha256.Sum256(b)
				digest = hex.EncodeToString(s[:])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": map[string]any{"path": f.path, "sha256": digest, "mode": "block"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

type policyFixture struct {
	db     *sql.DB
	cfg    *config.Config
	waf    *fakeWAF
	router chi.Router
}

func newPolicyFixture(t *testing.T) *policyFixture {
	t.Helper()
	db, _, cfg, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	wafBreaker = appMW.NewCircuitBreaker(3, 30*time.Second)
	t.Cleanup(func() { wafBreaker = appMW.NewCircuitBreaker(3, 30*time.Second) })
	cfg.WAFPolicyFile = filepath.Join(cfg.ConfigDir, "waf_policy.json")
	waf := newFakeWAF(t, cfg.WAFPolicyFile)
	cfg.WAFURL = waf.srv.URL
	r := chi.NewRouter()
	signedIn := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), appMW.CtxUsername, "admin")))
		})
	}
	NewWAFPolicyHandlers(db, cfg).Register(r, signedIn)
	return &policyFixture{db: db, cfg: cfg, waf: waf, router: r}
}

func (f *policyFixture) do(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (f *policyFixture) file(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(f.cfg.WAFPolicyFile)
	if err != nil {
		return ""
	}
	return string(b)
}

func (f *policyFixture) audits(t *testing.T, action string) int {
	t.Helper()
	var n int
	_ = f.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = ?", action).Scan(&n)
	return n
}

// An exception from the access log is validated by the WAF, written readable
// by the WAF's user, reloaded and audited; the same scope again is not added
// twice.
func TestAddWAFExceptionWritesAValidatedFile(t *testing.T) {
	f := newPolicyFixture(t)
	code, out := f.do(t, "POST", "/api/waf/policy/exceptions", `{"rule":"CRS-942290","host":"shop.example","target":"ARGS:pwd","comment":"login form"}`)
	if code != 200 || out["data"].(map[string]any)["added"] != true {
		t.Fatalf("add: %d %v", code, out)
	}
	var file wafPolicyFile
	if err := json.Unmarshal([]byte(f.file(t)), &file); err != nil || file.Version != 1 || len(file.Exceptions) != 1 ||
		file.Exceptions[0] != (wafPolicyException{Rule: "CRS-942290", Host: "shop.example", Target: "ARGS:pwd", Comment: "login form"}) {
		t.Errorf("file: %s (%v)", f.file(t), err)
	}
	st, _ := os.Stat(f.cfg.WAFPolicyFile)
	if st.Mode().Perm() != 0o644 {
		t.Errorf("file mode %v, want 0644: the WAF runs as another user and must read it", st.Mode().Perm())
	}
	if f.waf.validates.Load() != 1 || f.waf.reloads.Load() != 1 || f.audits(t, "add_waf_exception") != 1 {
		t.Errorf("validates %d, reloads %d, audit rows %d", f.waf.validates.Load(), f.waf.reloads.Load(), f.audits(t, "add_waf_exception"))
	}
	code, out = f.do(t, "POST", "/api/waf/policy/exceptions", `{"rule":"CRS-942290","host":"Shop.Example","target":"args:pwd","comment":"again"}`)
	if code != 200 || out["data"].(map[string]any)["added"] != false || strings.Count(f.file(t), "CRS-942290") != 1 {
		t.Errorf("the same scope again: %d %v, file %s", code, out, f.file(t))
	}
}

// A policy the WAF refuses is not written, and the reason is the WAF's.
func TestRefusedWAFExceptionIsNotWritten(t *testing.T) {
	f := newPolicyFixture(t)
	code, out := f.do(t, "POST", "/api/waf/policy/exceptions", `{"rule":"REFUSED-001","host":"shop.example"}`)
	if code != http.StatusUnprocessableEntity || !strings.Contains(out["detail"].(string), `unknown rule \"REFUSED-001\"`) && !strings.Contains(out["detail"].(string), `unknown rule "REFUSED-001"`) {
		t.Errorf("refused: %d %v", code, out)
	}
	if f.file(t) != "" || f.waf.reloads.Load() != 0 || f.audits(t, "add_waf_exception") != 0 {
		t.Errorf("a refused policy was written: %q", f.file(t))
	}
}

// With the WAF unreachable nothing is written: a file the WAF would refuse
// at its next start would stop it.
func TestNothingIsWrittenWithoutTheWAF(t *testing.T) {
	f := newPolicyFixture(t)
	f.waf.srv.Close()
	code, out := f.do(t, "POST", "/api/waf/policy/exceptions", `{"rule":"CRS-942290","host":"shop.example"}`)
	if code != http.StatusServiceUnavailable || !strings.Contains(out["detail"].(string), "nothing was written") {
		t.Errorf("WAF down: %d %v", code, out)
	}
	if f.file(t) != "" {
		t.Errorf("written without the WAF: %q", f.file(t))
	}
}

// PUT replaces the file only when it is the one the caller read.
func TestPutWAFPolicyNeedsTheDigestItWasReadAt(t *testing.T) {
	f := newPolicyFixture(t)
	code, out := f.do(t, "GET", "/api/waf/policy", "")
	data := out["data"].(map[string]any)
	if code != 200 || data["exists"] != false || data["sha256"] != "" || data["in_force"] != true {
		t.Fatalf("GET with no file: %d %v", code, out)
	}
	put := func(sha string) (int, map[string]any) {
		return f.do(t, "PUT", "/api/waf/policy", `{"policy":{"version":1,"mode":"observe","observe_rules":["SQLi-001"]},"sha256":"`+sha+`"}`)
	}
	if code, out = f.do(t, "PUT", "/api/waf/policy", `{"policy":{"version":1}}`); code != http.StatusBadRequest {
		t.Errorf("PUT without sha256: %d %v", code, out)
	}
	if code, out = put("0000"); code != http.StatusConflict {
		t.Errorf("PUT with a digest that is not the file's: %d %v", code, out)
	}
	code, out = put("")
	if code != 200 || !strings.Contains(f.file(t), `"mode": "observe"`) || f.audits(t, "update_waf_policy") != 1 {
		t.Fatalf("PUT on the absent file: %d %v, file %s", code, out, f.file(t))
	}
	newSHA := out["data"].(map[string]any)["sha256"].(string)
	if code, _ = put(""); code != http.StatusConflict {
		t.Errorf("a second PUT from the same read: %d, want 409", code)
	}
	_, out = f.do(t, "GET", "/api/waf/policy", "")
	data = out["data"].(map[string]any)
	if data["sha256"] != newSHA || data["in_force"] != true || data["path_mismatch"] != nil {
		t.Errorf("GET after the PUT: %v", data)
	}
}

// A hand-edited file that does not parse is reported, not overwritten by an
// added exception; a PUT from its digest replaces it.
func TestABrokenPolicyFileIsReportedNotMerged(t *testing.T) {
	f := newPolicyFixture(t)
	if err := os.WriteFile(f.cfg.WAFPolicyFile, []byte(`{"version":1,"exceptions":[`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, out := f.do(t, "GET", "/api/waf/policy", "")
	data := out["data"].(map[string]any)
	if data["policy"] != nil || !strings.Contains(data["file_error"].(string), "does not parse") {
		t.Fatalf("GET of a broken file: %v", data)
	}
	if code, _ := f.do(t, "POST", "/api/waf/policy/exceptions", `{"rule":"CRS-942290","host":"a.example"}`); code != http.StatusConflict {
		t.Errorf("exception added to a broken file: %d", code)
	}
	if code, _ := f.do(t, "PUT", "/api/waf/policy", `{"policy":{"version":1},"sha256":"`+data["sha256"].(string)+`"}`); code != 200 {
		t.Errorf("PUT from the broken file's digest: %d", code)
	}
}

// Observing a rule adds it once.
func TestObserveWAFRule(t *testing.T) {
	f := newPolicyFixture(t)
	for i, want := range []bool{true, false} {
		code, out := f.do(t, "POST", "/api/waf/policy/observe-rules", `{"rule":"XSS-003"}`)
		if code != 200 || out["data"].(map[string]any)["added"] != want {
			t.Errorf("call %d: %d %v", i, code, out)
		}
	}
	if strings.Count(f.file(t), "XSS-003") != 1 || f.audits(t, "observe_waf_rule") != 1 {
		t.Errorf("file %s", f.file(t))
	}
}

// A path the WAF reads that is not the one the backend writes is reported.
func TestWAFPolicyPathMismatchIsReported(t *testing.T) {
	f := newPolicyFixture(t)
	f.waf.path = "/elsewhere/waf_policy.json"
	_, out := f.do(t, "GET", "/api/waf/policy", "")
	if m, _ := out["data"].(map[string]any)["path_mismatch"].(string); !strings.Contains(m, "WAF_POLICY_FILE") {
		t.Errorf("no path mismatch reported: %v", out)
	}
}

// A waf_block alert is kept under its event ID and read back, with the
// address masked in GDPR mode; an ID that is not the WAF's is refused.
func TestWAFBlockAlertIsKeptForTheAccessLog(t *testing.T) {
	f := newPolicyFixture(t)
	notify := NewNotifyQueue(t.Context(), f.db, strings.Repeat("0", 64))
	sec := NewSecurityHandlers(f.db, nil, f.cfg, notify)
	alert := models.InternalAlert{EventType: "waf_block", Message: "WAF blocked URL", Level: "error", Details: map[string]any{
		"event_id": "dmi3i63n5d9c-2", "client_ip": "192.0.2.7", "host": "shop.example", "path": "/login",
		"url": "http://shop.example/login?pwd=x", "source": "URL", "blocked_by": "crs", "score": 5, "crs_score": 5,
		"rules": []string{"CRS-942290"}, "categories": []string{"CRS_SQLI"},
		"crs_targets": []map[string]string{{"rule": "CRS-942290", "target": "ARGS:pwd"}},
	}}
	body, _ := json.Marshal(alert)
	for range 2 { // the WAF retries an alert it could not deliver
		w := httptest.NewRecorder()
		sec.ReceiveAlert(w, httptest.NewRequest("POST", "/api/internal/alert", bytes.NewReader(body)))
		if w.Code != 200 {
			t.Fatalf("alert: %d", w.Code)
		}
	}
	code, out := f.do(t, "GET", "/api/waf/events/dmi3i63n5d9c-2", "")
	d, _ := out["data"].(map[string]any)
	got, _ := json.Marshal(map[string]any{"host": d["host"], "path": d["path"], "by": d["blocked_by"], "rules": d["rules"], "targets": d["crs_targets"], "ip": d["client_ip"]})
	if code != 200 || string(got) != `{"by":"crs","host":"shop.example","ip":"192.0.2.7","path":"/login","rules":["CRS-942290"],"targets":[{"rule":"CRS-942290","target":"ARGS:pwd"}]}` {
		t.Errorf("event: %d %s", code, got)
	}
	_, _ = f.db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES ('gdpr_mode','true')")
	privacy.InvalidateDB(f.db)
	t.Cleanup(func() { privacy.InvalidateDB(f.db) })
	if _, out = f.do(t, "GET", "/api/waf/events/dmi3i63n5d9c-2", ""); out["data"].(map[string]any)["client_ip"] == "192.0.2.7" {
		t.Error("GDPR mode on, the address read back unmasked")
	}
	if code, _ = f.do(t, "GET", "/api/waf/events/nope", ""); code != http.StatusBadRequest {
		t.Errorf("not an event ID: %d", code)
	}
	if code, _ = f.do(t, "GET", "/api/waf/events/abc-1", ""); code != http.StatusNotFound {
		t.Errorf("unknown event: %d", code)
	}
	var n int
	_ = f.db.QueryRow("SELECT COUNT(*) FROM waf_events").Scan(&n)
	if n != 1 {
		t.Errorf("%d rows for one event delivered twice", n)
	}
}

// An access log row of a WAF block carries its event ID, the key of
// GET /api/waf/events/{id}; other rows carry null.
func TestAccessLogRowsCarryTheWAFEventID(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	for _, q := range []string{
		`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, blocked, event_id, block_reason)
		 VALUES(datetime('now'), strftime('%s','now'), '192.0.2.8', 'GET', 'http://shop.example/login', 'TCP_DENIED/403', 1, 'dmi3i63n5d9c-2', 'waf')`,
		`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status)
		 VALUES(datetime('now'), strftime('%s','now'), '192.0.2.8', 'GET', 'http://shop.example/', 'TCP_MISS/200')`,
		// The tailer stores "" for a row with no event ID.
		`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, event_id)
		 VALUES(datetime('now'), strftime('%s','now'), '192.0.2.8', 'GET', 'http://shop.example/a', 'TCP_MISS/200', '')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	NewLogHandlers(db).GetLogs(w, httptest.NewRequest("GET", "/api/logs?sort=id&order=asc", nil))
	var out struct {
		Data []map[string]any `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	ids := map[any]bool{}
	for _, row := range out.Data {
		ids[row["event_id"]] = true
	}
	if len(out.Data) != 3 || !ids["dmi3i63n5d9c-2"] || !ids[nil] || ids[""] {
		t.Errorf("event_id on the rows: %s", w.Body.String())
	}
}
