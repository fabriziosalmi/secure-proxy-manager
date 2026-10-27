package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

const (
	testProxyUser = "office-laptop"
	testProxyPass = "correct-horse-battery"
)

func proxyLoginHandlers(t *testing.T) (*SettingsHandlers, string) {
	t.Helper()
	db, _, cfg, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	cfg.EncryptionKey = testEncKey
	return NewSettingsHandlers(db, cfg), filepath.Join(cfg.ConfigDir, proxyUsersFileName)
}

func seedSetting(t *testing.T, h *SettingsHandlers, key, value string) {
	t.Helper()
	if _, err := h.db.Exec("INSERT INTO settings(setting_name,setting_value) VALUES(?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value=excluded.setting_value", key, value); err != nil {
		t.Fatalf("seed %s: %v", key, err)
	}
}

// seedProxyLogin stores the three settings the file is derived from.
func seedProxyLogin(t *testing.T, h *SettingsHandlers, on bool, user, password string) {
	t.Helper()
	seedSetting(t, h, settingProxyAuth, map[bool]string{true: "true", false: "false"}[on])
	seedSetting(t, h, settingProxyUsername, user)
	if password == "" {
		seedSetting(t, h, settingProxyPassword, "")
	} else {
		storeSecret(t, h, settingProxyPassword, password)
	}
}

// userLine is the one line basic_ncsa_auth reads from the file.
func userLine(t *testing.T, data []byte) (name, hash string) {
	t.Helper()
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("want exactly one user line, got %q", data)
	}
	name, hash, ok := strings.Cut(lines[0], ":")
	if !ok {
		t.Fatalf("user line has no colon: %q", lines[0])
	}
	return name, hash
}

func TestSyncProxyUsersWritesABcryptLineThatVerifies(t *testing.T) {
	h, path := proxyLoginHandlers(t)
	seedProxyLogin(t, h, true, testProxyUser, testProxyPass)

	changed, err := h.SyncProxyUsers()
	if err != nil || !changed {
		t.Fatalf("SyncProxyUsers = %v, %v; want a written file", changed, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !proxyUsersManaged(data) {
		t.Errorf("the file does not start with the backend's marker: %q", data)
	}
	name, hash := userLine(t, data)
	if name != testProxyUser {
		t.Errorf("user = %q, want %q", name, testProxyUser)
	}
	if !strings.HasPrefix(hash, "$2a$10$") {
		t.Errorf("hash %q is not bcrypt at the default cost ($2a$10$, which the proxy image's basic_ncsa_auth accepts)", hash)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(testProxyPass)) != nil {
		t.Error("the hash does not verify the stored password")
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("not-the-password")) == nil {
		t.Error("the hash verifies a wrong password")
	}
	if bytes.Contains(data, []byte(testProxyPass)) {
		t.Fatal("the password is in the file in clear")
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 0640 (owner and the proxy group)", fi.Mode().Perm())
	}

	// In line already: no rewrite, so no needless proxy reload.
	before, _ := os.Stat(path)
	if changed, err := h.SyncProxyUsers(); err != nil || changed {
		t.Fatalf("second SyncProxyUsers = %v, %v; want no change", changed, err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Error("a file already in line was rewritten")
	}
}

// The file is replaced by a rename, never truncated in place: a reader that
// has the old file open keeps reading the old content, and no temp file is
// left behind.
func TestSyncProxyUsersReplacesTheFileAtomically(t *testing.T) {
	h, path := proxyLoginHandlers(t)
	seedProxyLogin(t, h, true, testProxyUser, testProxyPass)
	if _, err := h.SyncProxyUsers(); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	oldInfo, _ := old.Stat()

	seedSetting(t, h, settingProxyUsername, "second-user")
	if changed, err := h.SyncProxyUsers(); err != nil || !changed {
		t.Fatalf("SyncProxyUsers after a new username = %v, %v", changed, err)
	}
	newInfo, _ := os.Stat(path)
	if os.SameFile(oldInfo, newInfo) {
		t.Fatal("the file was rewritten in place: a reader could see it half written")
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(old); err != nil {
		t.Fatal(err)
	}
	if name, _ := userLine(t, buf.Bytes()); name != testProxyUser {
		t.Errorf("the open handle reads %q, want the old file's %q", name, testProxyUser)
	}
	now, _ := os.ReadFile(path)
	if name, _ := userLine(t, now); name != "second-user" {
		t.Errorf("the path reads %q, want second-user", name)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.Contains(e.Name(), proxyUsersFileName+".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestSyncProxyUsersRemovesTheFileWhenLoginOrCredentialsGo(t *testing.T) {
	for _, tc := range []struct {
		name     string
		on       bool
		user, pw string
	}{
		{"login turned off", false, testProxyUser, testProxyPass},
		{"username removed", true, "", testProxyPass},
		{"password removed", true, testProxyUser, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, path := proxyLoginHandlers(t)
			seedProxyLogin(t, h, true, testProxyUser, testProxyPass)
			if _, err := h.SyncProxyUsers(); err != nil {
				t.Fatal(err)
			}
			seedProxyLogin(t, h, tc.on, tc.user, tc.pw)
			changed, err := h.SyncProxyUsers()
			if err != nil || !changed {
				t.Fatalf("SyncProxyUsers = %v, %v; want the file removed", changed, err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Errorf("the file is still there (%v)", err)
			}
		})
	}
}

// A file the backend did not write (an operator who passes BASIC_AUTH_* to
// the proxy, whose generator creates it) is never removed; credentials set
// in Settings replace it.
func TestSyncProxyUsersLeavesAFileItDidNotWrite(t *testing.T) {
	h, path := proxyLoginHandlers(t)
	theirs := []byte("ops:$6$salt$hash\n")
	if err := os.WriteFile(path, theirs, 0o640); err != nil {
		t.Fatal(err)
	}
	seedProxyLogin(t, h, true, "", "")
	if changed, err := h.SyncProxyUsers(); err != nil || changed {
		t.Fatalf("SyncProxyUsers = %v, %v; want the file left alone", changed, err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, theirs) {
		t.Fatalf("the operator's file was changed: %q", got)
	}
	seedProxyLogin(t, h, true, testProxyUser, testProxyPass)
	if changed, err := h.SyncProxyUsers(); err != nil || !changed {
		t.Fatalf("SyncProxyUsers with credentials = %v, %v", changed, err)
	}
	got, _ := os.ReadFile(path)
	if name, _ := userLine(t, got); name != testProxyUser {
		t.Errorf("the stored credentials did not replace the file: %q", got)
	}
}

// A password stored with another key cannot be hashed again: the file keeps
// the hash of the password the operator set.
func TestSyncProxyUsersKeepsTheFileWhenThePasswordCannotBeRead(t *testing.T) {
	h, path := proxyLoginHandlers(t)
	seedProxyLogin(t, h, true, testProxyUser, testProxyPass)
	if _, err := h.SyncProxyUsers(); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(path)
	h.cfg.EncryptionKey = "1111111111111111111111111111111111111111111111111111111111111111"
	if changed, err := h.SyncProxyUsers(); err != nil || changed {
		t.Fatalf("SyncProxyUsers = %v, %v; want no change", changed, err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, want) {
		t.Error("the file changed although the stored password could not be read")
	}
}

func TestProxyLoginValidators(t *testing.T) {
	for _, tc := range []struct {
		key, value string
		ok         bool
	}{
		{settingProxyUsername, "", true},
		{settingProxyUsername, "office-laptop", true},
		{settingProxyUsername, "first.last@example.org", true},
		{settingProxyUsername, "a", true},
		{settingProxyUsername, strings.Repeat("u", 64), true},
		{settingProxyUsername, strings.Repeat("u", 65), false},
		{settingProxyUsername, "user:name", false},
		{settingProxyUsername, "user\nother:hash", false},
		{settingProxyUsername, "two words", false},
		{settingProxyUsername, "#comment", false},
		{settingProxyPassword, "", true},
		{settingProxyPassword, "twelve-chars", true},
		{settingProxyPassword, "eleven-char", false},
		{settingProxyPassword, "with spaces and : colons", true},
		{settingProxyPassword, "line-one-long\nline-two", false},
		{settingProxyPassword, "carriage-return\r", false},
		{settingProxyPassword, strings.Repeat("p", 72), true},
		{settingProxyPassword, strings.Repeat("p", 73), false},
	} {
		err := validateSettingValue(tc.key, tc.value)
		if (err == nil) != tc.ok {
			t.Errorf("%s=%q: err = %v, want ok=%v", tc.key, tc.value, err, tc.ok)
		}
	}
}

// postRouted goes through the router, as the UI does.
func postRouted(t *testing.T, h *SettingsHandlers, query string, body map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := chi.NewRouter()
	h.Register(r, func(next http.Handler) http.Handler { return next })
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/settings"+query, bytes.NewReader(raw)))
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp
}

func fieldErrors(resp map[string]any) map[string]any {
	errs, _ := resp["errors"].(map[string]any)
	return errs
}

// From POST /api/settings to the file the proxy reads: the credentials are
// stored (the password encrypted), the file verifies them, the proxy is asked
// to reload, and turning login off removes the file.
func TestPostSettingsWritesTheProxyPasswordFile(t *testing.T) {
	h, path := proxyLoginHandlers(t)
	trigger := filepath.Join(h.cfg.ConfigDir, ".reload-squid")

	w, resp := postRouted(t, h, "", map[string]string{
		settingProxyAuth: "true", settingProxyUsername: testProxyUser, settingProxyPassword: testProxyPass,
	})
	if w.Code != http.StatusOK || resp["status"] != "success" {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	stored := storedValue(t, h, settingProxyPassword)
	if !appcrypto.IsEncrypted(stored) {
		t.Fatalf("the password is not stored encrypted: %q", stored)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no password file after the save: %v", err)
	}
	name, hash := userLine(t, data)
	if name != testProxyUser || bcrypt.CompareHashAndPassword([]byte(hash), []byte(testProxyPass)) != nil {
		t.Fatalf("the file does not verify the saved credentials: %q", data)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.ConfigDir, "proxy_auth_enabled")); err != nil {
		t.Errorf("the login toggle marker was not written: %v", err)
	}
	if _, err := os.Stat(trigger); err != nil {
		t.Errorf("the proxy was not asked to reload after the file changed: %v", err)
	}

	// A later save of the same section that does not retype the password
	// keeps it and leaves the file alone.
	before, _ := os.Stat(path)
	if w, _ := postRouted(t, h, "", map[string]string{settingProxyAuth: "true", settingProxyUsername: testProxyUser}); w.Code != http.StatusOK {
		t.Fatalf("save without the password: %d %s", w.Code, w.Body.String())
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Error("a save that did not change the credentials rewrote the file")
	}

	// Login off: the file goes with it.
	if w, _ := postRouted(t, h, "", map[string]string{settingProxyAuth: "false", settingProxyUsername: testProxyUser}); w.Code != http.StatusOK {
		t.Fatalf("turn off: %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the password file is still there with login off (%v)", err)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.ConfigDir, "proxy_auth_enabled")); !os.IsNotExist(err) {
		t.Errorf("the toggle marker is still there with login off (%v)", err)
	}

	// Credentials removed with login off: allowed, and the secret is gone.
	if w, _ := postRouted(t, h, "?clear="+settingProxyPassword, map[string]string{settingProxyAuth: "false"}); w.Code != http.StatusOK {
		t.Fatalf("clear with login off: %d %s", w.Code, w.Body.String())
	}
	if got := storedValue(t, h, settingProxyPassword); got != "" {
		t.Errorf("the password was not removed: %q", got)
	}
}

// Login cannot be turned on, or its credentials removed while it is on,
// without both credentials: the proxy would refuse every client.
func TestPostSettingsRefusesLoginWithoutCredentials(t *testing.T) {
	h, path := proxyLoginHandlers(t)

	w, resp := postRouted(t, h, "", map[string]string{settingProxyAuth: "true"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("login on with no credentials: %d, want 400", w.Code)
	}
	errs := fieldErrors(resp)
	for _, k := range []string{settingProxyUsername, settingProxyPassword} {
		if msg, _ := errs[k].(string); !strings.Contains(msg, "refuses every client") {
			t.Errorf("%s: message %q does not say what happens", k, msg)
		}
	}
	if got := storedValue(t, h, settingProxyAuth); got == "true" {
		t.Error("the refused save turned login on")
	}

	if w, _ := postRouted(t, h, "", map[string]string{
		settingProxyAuth: "true", settingProxyUsername: testProxyUser, settingProxyPassword: testProxyPass,
	}); w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	w, resp = postRouted(t, h, "?clear="+settingProxyPassword, map[string]string{settingProxyAuth: "true", settingProxyUsername: testProxyUser})
	if w.Code != http.StatusBadRequest || fieldErrors(resp)[settingProxyPassword] == nil {
		t.Fatalf("clearing the password with login on: %d %s, want 400 on the password", w.Code, w.Body.String())
	}
	w, resp = postRouted(t, h, "", map[string]string{settingProxyAuth: "true", settingProxyUsername: ""})
	if w.Code != http.StatusBadRequest || fieldErrors(resp)[settingProxyUsername] == nil {
		t.Fatalf("emptying the username with login on: %d %s, want 400 on the username", w.Code, w.Body.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("a refused save removed the password file: %v", err)
	}

	// A bad value is refused under its own field.
	w, resp = postRouted(t, h, "", map[string]string{settingProxyAuth: "true", settingProxyUsername: "bad:name", settingProxyPassword: "short"})
	errs = fieldErrors(resp)
	if w.Code != http.StatusBadRequest || errs[settingProxyUsername] == nil || errs[settingProxyPassword] == nil {
		t.Fatalf("bad values: %d %s, want 400 on both fields", w.Code, w.Body.String())
	}
}

// The single-key route applies the same rule and writes the file too.
func TestPutSettingKeepsTheProxyLoginConsistent(t *testing.T) {
	h, path := proxyLoginHandlers(t)
	put := func(name, value string) *httptest.ResponseRecorder {
		r := chi.NewRouter()
		h.Register(r, func(next http.Handler) http.Handler { return next })
		raw, _ := json.Marshal(map[string]string{"value": value})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("PUT", "/api/settings/"+name, bytes.NewReader(raw)))
		return w
	}
	if w := put(settingProxyAuth, "true"); w.Code != http.StatusBadRequest {
		t.Fatalf("PUT login on with no credentials: %d, want 400", w.Code)
	}
	if w := put(settingProxyUsername, testProxyUser); w.Code != http.StatusOK {
		t.Fatalf("PUT username: %d %s", w.Code, w.Body.String())
	}
	if w := put(settingProxyPassword, testProxyPass); w.Code != http.StatusOK {
		t.Fatalf("PUT password: %d %s", w.Code, w.Body.String())
	}
	if w := put(settingProxyAuth, "true"); w.Code != http.StatusOK {
		t.Fatalf("PUT login on: %d %s", w.Code, w.Body.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no password file after PUT: %v", err)
	}
	if _, hash := userLine(t, data); bcrypt.CompareHashAndPassword([]byte(hash), []byte(testProxyPass)) != nil {
		t.Error("the file does not verify the password set by PUT")
	}
	if w := put(settingProxyPassword, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("PUT an empty password with login on: %d, want 400", w.Code)
	}
}

// GET /api/settings never returns the proxy password, its ciphertext or the
// hash: only that one is stored.
func TestGetAllNeverReturnsTheProxyPassword(t *testing.T) {
	h, _ := proxyLoginHandlers(t)
	if w, _ := postRouted(t, h, "", map[string]string{
		settingProxyAuth: "true", settingProxyUsername: testProxyUser, settingProxyPassword: testProxyPass,
	}); w.Code != http.StatusOK {
		t.Fatalf("save: %d", w.Code)
	}
	file, _ := os.ReadFile(filepath.Join(h.cfg.ConfigDir, proxyUsersFileName))
	_, hash := userLine(t, file)

	w := httptest.NewRecorder()
	h.GetAll(w, httptest.NewRequest("GET", "/api/settings", nil))
	body := w.Body.Bytes()
	for what, s := range map[string]string{"password": testProxyPass, "ciphertext": storedValue(t, h, settingProxyPassword), "hash": hash} {
		if bytes.Contains(body, []byte(s)) {
			t.Fatalf("GET /api/settings returned the %s", what)
		}
	}
	var resp struct {
		Data []struct {
			Name   string `json:"setting_name"`
			Value  string `json:"setting_value"`
			Secret bool   `json:"secret"`
			IsSet  bool   `json:"is_set"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, row := range resp.Data {
		switch row.Name {
		case settingProxyPassword:
			seen++
			if !row.Secret || !row.IsSet || row.Value != "" {
				t.Errorf("proxy_auth_password: want secret, set, no value; got %+v", row)
			}
		case settingProxyUsername:
			seen++
			if row.Secret || row.Value != testProxyUser {
				t.Errorf("proxy_auth_username is plain and returned: got %+v", row)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("rows missing: saw %d of 2", seen)
	}
}

// A restore that carries the credentials reaches the file, the password
// included although the restore writes no secret to the artefacts itself.
func TestRestoreWritesTheProxyPasswordFile(t *testing.T) {
	h, path := proxyLoginHandlers(t)
	enc, _ := appcrypto.Encrypt(testProxyPass, h.cfg.EncryptionKey)
	mh := &MaintenanceHandlers{db: h.db, cfg: h.cfg}
	raw, _ := json.Marshal(map[string]any{"backup_version": 2, "settings": map[string]string{
		settingProxyAuth: "true", settingProxyUsername: testProxyUser, settingProxyPassword: enc,
	}})
	w := httptest.NewRecorder()
	mh.RestoreConfig(w, httptest.NewRequest("POST", "/api/maintenance/restore-config", bytes.NewReader(raw)))
	if w.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no password file after the restore: %v", err)
	}
	if _, hash := userLine(t, data); bcrypt.CompareHashAndPassword([]byte(hash), []byte(testProxyPass)) != nil {
		t.Error("the restored password does not verify")
	}
}

// A backup that carries only the password (the other two already stored)
// still reaches the file: the restore writes no secret to the artefacts.
func TestRestoreOfThePasswordAloneWritesTheFile(t *testing.T) {
	h, path := proxyLoginHandlers(t)
	seedProxyLogin(t, h, true, testProxyUser, "")
	enc, _ := appcrypto.Encrypt(testProxyPass, h.cfg.EncryptionKey)
	mh := &MaintenanceHandlers{db: h.db, cfg: h.cfg}
	raw, _ := json.Marshal(map[string]any{"config": map[string]string{settingProxyPassword: enc}})
	w := httptest.NewRecorder()
	mh.RestoreConfig(w, httptest.NewRequest("POST", "/api/maintenance/restore-config", bytes.NewReader(raw)))
	if w.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no password file after restoring the password: %v", err)
	}
	if _, hash := userLine(t, data); bcrypt.CompareHashAndPassword([]byte(hash), []byte(testProxyPass)) != nil {
		t.Error("the restored password does not verify")
	}
}

// Startup brings the file in line: an upgrade from a version that did not
// write it, with credentials already stored, gets one and a reload.
func TestSyncProxyUsersAtStartup(t *testing.T) {
	h, path := proxyLoginHandlers(t)
	seedProxyLogin(t, h, true, testProxyUser, testProxyPass)
	h.SyncProxyUsersAtStartup()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("no password file after startup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.ConfigDir, ".reload-squid")); err != nil {
		t.Errorf("no reload requested: %v", err)
	}
}

func TestReadProxyAuthStatus(t *testing.T) {
	dir := t.TempDir()
	if readProxyAuthStatus(dir) != nil {
		t.Error("no file must read as no record")
	}
	for _, tc := range []struct {
		raw  string
		want *ProxyAuthStatus
	}{
		{`{"version":1,"state":"no_credentials","users":0,"written_at":5}`, &ProxyAuthStatus{State: "no_credentials", Users: 0, WrittenAt: 5}},
		{`{"version":1,"state":"enforced","users":1,"written_at":6}`, &ProxyAuthStatus{State: "enforced", Users: 1, WrittenAt: 6}},
		{`{"version":1,"state":"off","users":0,"written_at":7}`, &ProxyAuthStatus{State: "off", Users: 0, WrittenAt: 7}},
		{`{"version":2,"state":"off","users":0}`, nil},
		{`{"version":1,"state":"open","users":0}`, nil},
		{`{"version":1,"state":"off"}`, nil},
		{`not json`, nil},
	} {
		if err := os.WriteFile(filepath.Join(dir, proxyAuthStatusFileName), []byte(tc.raw), 0o644); err != nil {
			t.Fatal(err)
		}
		got := readProxyAuthStatus(dir)
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: got %+v, want %+v", tc.raw, got, tc.want)
		}
	}
}

// GET /api/status carries what the proxy reported, so the dashboard can say
// that every client is refused.
func TestStatusReportsTheProxyLoginState(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.ProxyURL = "http://127.0.0.1:1" // nothing listens: the probe fails fast
	if err := os.WriteFile(filepath.Join(cfg.ConfigDir, proxyAuthStatusFileName),
		[]byte(`{"version":1,"state":"no_credentials","users":0,"written_at":9}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Data struct {
			ProxyAuth *ProxyAuthStatus `json:"proxy_auth"`
		} `json:"data"`
	}
	getJSON(t, NewAnalyticsHandlers(db, cfg).Status, "/api/status", &resp)
	if resp.Data.ProxyAuth == nil || resp.Data.ProxyAuth.State != "no_credentials" {
		t.Fatalf("proxy_auth = %+v, want the proxy's no_credentials record", resp.Data.ProxyAuth)
	}
}

func fileGid(t *testing.T, path string) int {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return int(fi.Sys().(*syscall.Stat_t).Gid)
}

// The proxy's helper reads the password file through the proxy group, so the
// backend gives the file that group itself: on a new file too, and over a
// file that has another group. The test stands a group of its own process in
// for 13 (the compose files add 13 to the backend; the ACL matrix runs that).
func TestWriteProxyUsersFileGivesTheProxyGroup(t *testing.T) {
	dir := t.TempDir()
	dirGid := fileGid(t, dir) // BSD and macOS give a new file its directory's group
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	target := -1
	for _, g := range groups {
		if g != dirGid && g != os.Getegid() {
			target = g
			break
		}
	}
	if target < 0 {
		t.Skip("the test process has no supplementary group besides its own and the temp dir's; the ACL matrix covers the group with --group-add 13")
	}
	old := proxyGroupID
	proxyGroupID = target
	t.Cleanup(func() { proxyGroupID = old })

	path := filepath.Join(dir, proxyUsersFileName)
	if err := writeProxyUsersFile(path, []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	if got := fileGid(t, path); got != target {
		t.Fatalf("new file: group %d, want the proxy group %d", got, target)
	}
	if err := os.Chown(path, -1, dirGid); err != nil {
		t.Fatal(err)
	}
	if err := writeProxyUsersFile(path, []byte("second\n")); err != nil {
		t.Fatal(err)
	}
	if got := fileGid(t, path); got != target {
		t.Fatalf("replaced file: group %d, want the proxy group %d", got, target)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != proxyUsersPerm {
		t.Fatalf("mode %o, want %o", fi.Mode().Perm(), proxyUsersPerm)
	}
}

// A backend that is not in the proxy group (a compose file without group_add)
// still writes the file, and says in the log that the proxy refuses the new
// credentials until it reloads.
func TestWriteProxyUsersFileWarnsWhenItCannotSetTheProxyGroup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may set any group")
	}
	groups, _ := os.Getgroups()
	member := map[int]bool{os.Getegid(): true}
	for _, g := range groups {
		member[g] = true
	}
	foreign := -1
	for g := 1; g < 1000; g++ {
		if !member[g] {
			foreign = g
			break
		}
	}
	old := proxyGroupID
	proxyGroupID = foreign
	t.Cleanup(func() { proxyGroupID = old })
	var logs bytes.Buffer
	oldLog := log.Logger
	log.Logger = zerolog.New(&logs)
	t.Cleanup(func() { log.Logger = oldLog })

	path := filepath.Join(t.TempDir(), proxyUsersFileName)
	if err := writeProxyUsersFile(path, []byte("data\n")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "data\n" {
		t.Fatalf("file holds %q", got)
	}
	if !strings.Contains(logs.String(), `"level":"warn"`) || !strings.Contains(logs.String(), "407") {
		t.Fatalf("no warning naming the 407 window: %s", logs.String())
	}
}
