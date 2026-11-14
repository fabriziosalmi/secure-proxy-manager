package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func readFile(t *testing.T, path string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), true
}

// The proxy's upstream file follows the stored settings: absent while off or
// without a host, written with the login once both are set, in the secrets
// volume with mode 0600, and removed again when switched off. The domains
// that go direct are a dstdomain list in /config.
func TestTheUpstreamFileFollowsTheSettings(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	sh := NewSettingsHandlers(db, cfg)
	conf := filepath.Join(cfg.SecretsDir, upstreamConfName)
	direct := filepath.Join(cfg.ConfigDir, upstreamDirectName)

	setSetting(t, sh, map[string]string{settingUpstreamEnabled: "true"})
	if _, ok := readFile(t, conf); ok {
		t.Error("written without a host")
	}
	setSetting(t, sh, map[string]string{settingUpstreamHost: "proxy.corp.example", settingUpstreamPort: "8080"})
	got, ok := readFile(t, conf)
	if !ok || got != "UPSTREAM_HOST=proxy.corp.example\nUPSTREAM_PORT=8080\nUPSTREAM_MODE=always\n" {
		t.Errorf("conf = %q", got)
	}
	setSetting(t, sh, map[string]string{
		settingUpstreamUsername: "spm-svc", settingUpstreamPassword: "s3cr(e)t:pa$$",
		settingUpstreamMode: "fallback", settingUpstreamDirect: "corp.example, .Intranet.example, *.lab.example",
	})
	got, _ = readFile(t, conf)
	want := "UPSTREAM_HOST=proxy.corp.example\nUPSTREAM_PORT=8080\nUPSTREAM_MODE=fallback\nUPSTREAM_USER=spm-svc\nUPSTREAM_PASSWORD=s3cr(e)t:pa$$\n"
	if got != want {
		t.Errorf("conf = %q\nwant %q", got, want)
	}
	if st, err := os.Stat(conf); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v (%v), want 0600", st.Mode().Perm(), err)
	}
	if d, _ := readFile(t, direct); d != ".corp.example\n.intranet.example\n.lab.example\n" {
		t.Errorf("direct = %q", d)
	}
	// The password is stored encrypted and read back as a secret.
	var stored string
	_ = db.QueryRow(`SELECT setting_value FROM settings WHERE setting_name = ?`, settingUpstreamPassword).Scan(&stored)
	if stored == "s3cr(e)t:pa$$" || stored == "" {
		t.Errorf("stored password %q", stored)
	}
	w := httptest.NewRecorder()
	sh.GetAll(w, httptest.NewRequest("GET", "/api/settings", nil))
	var resp struct {
		Data []struct {
			Name   string `json:"setting_name"`
			Value  string `json:"setting_value"`
			Secret bool   `json:"secret"`
			IsSet  bool   `json:"is_set"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	for _, r := range resp.Data {
		if r.Name == settingUpstreamPassword && (r.Value != "" || !r.Secret || !r.IsSet) {
			t.Errorf("GET returns the password as %+v", r)
		}
	}

	setSetting(t, sh, map[string]string{settingUpstreamEnabled: "false", settingUpstreamDirect: ""})
	if _, ok := readFile(t, conf); ok {
		t.Error("still written after switching off")
	}
	if _, ok := readFile(t, direct); ok {
		t.Error("direct list still written after clearing it")
	}
}

// What cannot ride in a cache_peer login= token, or is not a host, is
// refused by the settings API.
func TestUpstreamSettingsAreValidated(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	sh := NewSettingsHandlers(db, cfg)
	for k, v := range map[string]string{
		settingUpstreamHost:     "http://proxy.corp.example",
		settingUpstreamPort:     "0",
		settingUpstreamMode:     "sometimes",
		settingUpstreamUsername: "user name",
	} {
		if w, _ := bulkUpdate(t, sh, "", map[string]string{k: v}); w.Code == http.StatusOK {
			t.Errorf("%s=%q was accepted", k, v)
		}
	}
	for _, pw := range []string{"with space", "has#hash", "per%cent", `quo"te`, `back\slash`, "it's"} {
		if w, _ := bulkUpdate(t, sh, "", map[string]string{settingUpstreamPassword: pw}); w.Code == http.StatusOK {
			t.Errorf("password %q was accepted", pw)
		}
	}
}

// A stored password the key no longer decrypts leaves the login out, and the
// rest of the upstream proxy is still written.
func TestAnUndecryptableUpstreamPasswordDropsOnlyTheLogin(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	sh := NewSettingsHandlers(db, cfg)
	setSetting(t, sh, map[string]string{
		settingUpstreamEnabled: "true", settingUpstreamHost: "10.0.0.9",
		settingUpstreamUsername: "u", settingUpstreamPassword: "p",
	})
	cfg.EncryptionKey = "11" + testEncKey[2:]
	if _, err := sh.SyncUpstreamProxy(); err != nil {
		t.Fatal(err)
	}
	got, _ := readFile(t, filepath.Join(cfg.SecretsDir, upstreamConfName))
	if got != "UPSTREAM_HOST=10.0.0.9\nUPSTREAM_PORT=3128\nUPSTREAM_MODE=always\n" {
		t.Errorf("conf = %q", got)
	}
}
