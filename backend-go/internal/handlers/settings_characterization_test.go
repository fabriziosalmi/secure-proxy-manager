package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// SECURE-QUAL-01. BulkUpdate is measured at cyclomatic complexity 37 over 137
// NLOC and is the handler that applies many settings at once — the path an
// operator uses to change proxy behaviour in bulk. Whether every setting is
// validated, encrypted, audited and propagated on every path through it cannot
// be established by reading; it has to be established by testing.
//
// This pins the OBSERVABLE behaviour before the function is split: what lands in
// the settings table, which artefact files exist or are removed afterwards, and
// what the caller is told. It is written to keep passing after the split — if it
// has to be edited to accommodate one, that refactor changed behaviour.

// snapshot is the fingerprint of one BulkUpdate call.
type settingsSnapshot struct {
	Status   string
	Code     int
	Settings map[string]string
	Files    []string // artefact files present under ConfigDir, sorted
}

func runBulkUpdate(t *testing.T, h *SettingsHandlers, cfgDir string, body map[string]string) settingsSnapshot {
	t.Helper()
	b, _ := json.Marshal(body)
	r := withUserContext(httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader(b)), "admin")
	w := httptest.NewRecorder()
	h.BulkUpdate(w, r)

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	status, _ := resp["status"].(string)

	settings := map[string]string{}
	rows, err := h.db.Query("SELECT setting_name, setting_value FROM settings")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k, v string
			_ = rows.Scan(&k, &v)
			settings[k] = v
		}
	}

	var files []string
	entries, _ := os.ReadDir(cfgDir)
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	return settingsSnapshot{Status: status, Code: w.Code, Settings: settings, Files: files}
}

func TestBulkUpdateBehaviour(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	t.Run("writes valid settings and audits them", func(t *testing.T) {
		got := runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{
			"proxy_port": "3129", "cache_size": "1500",
		})
		if got.Code != http.StatusOK || got.Status != "success" {
			t.Fatalf("got %d/%s", got.Code, got.Status)
		}
		if got.Settings["proxy_port"] != "3129" || got.Settings["cache_size"] != "1500" {
			t.Errorf("settings not persisted: %v", got.Settings)
		}
		var n int
		_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='update_settings'").Scan(&n)
		if n == 0 {
			t.Error("the bulk update was not audited")
		}
	})

	t.Run("rejects an invalid value for a validated key, and persists nothing", func(t *testing.T) {
		before := runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{})
		got := runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"proxy_port": "not-a-port"})
		if got.Code != http.StatusBadRequest {
			t.Errorf("an invalid port was accepted: %d", got.Code)
		}
		if got.Settings["proxy_port"] != before.Settings["proxy_port"] {
			t.Error("a rejected bulk update still changed the stored value")
		}
	})

	t.Run("skips protected keys instead of failing the whole update", func(t *testing.T) {
		// Seeded as "false" by Init, so writing "true" through BulkUpdate would
		// be a visible change if the key were writable.
		got := runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{
			"default_password_changed": "true", // internally managed
			"cache_size":               "1600",
		})
		if got.Code != http.StatusOK {
			t.Fatalf("a protected key failed the whole update: %d", got.Code)
		}
		if got.Settings["default_password_changed"] != "false" {
			t.Errorf("an internally-managed key was writable through BulkUpdate: %q",
				got.Settings["default_password_changed"])
		}
		if got.Settings["cache_size"] != "1600" {
			t.Error("the valid key in the same request was not applied")
		}
	})

	t.Run("a toggle creates its flag file and clearing it removes the file", func(t *testing.T) {
		on := runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"egress_default_deny": "true"})
		if !contains(on.Files, "egress_default_deny") {
			t.Fatalf("the toggle file was not created: %v", on.Files)
		}
		off := runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"egress_default_deny": "false"})
		if contains(off.Files, "egress_default_deny") {
			t.Errorf("the toggle file survived being switched off: %v", off.Files)
		}
	})

	t.Run("a list setting becomes a newline-separated ACL file", func(t *testing.T) {
		got := runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{
			"cache_bypass_domains": "a.test, b.test",
			"blocked_file_types":   "exe, .zip",
		})
		if got.Code != http.StatusOK {
			t.Fatalf("got %d", got.Code)
		}
		bypass, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "cache_bypass_domains.txt"))
		if err != nil {
			t.Fatalf("bypass list not written: %v", err)
		}
		// Each domain gains a leading dot: Squid's dstdomain ACL treats ".x" as
		// "x and every subdomain", which is what a bypass list means.
		if string(bypass) != ".a.test\n.b.test\n" {
			t.Errorf("bypass list = %q, want %q", bypass, ".a.test\n.b.test\n")
		}
		ft, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "blocked_file_types.txt"))
		if err != nil {
			t.Fatalf("file-type list not written: %v", err)
		}
		// Extensions become anchored regexes: the ACL is urlpath_regex, so
		// "exe" and ".zip" both normalise to \.ext$ — which is why a bare
		// extension and a dotted one produce the same rule.
		if string(ft) != "\\.exe$\n\\.zip$\n" {
			t.Errorf("file-type list = %q, want %q", ft, "\\.exe$\n\\.zip$\n")
		}
	})

	t.Run("an empty list setting empties the file rather than leaving it stale", func(t *testing.T) {
		_ = runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"cache_bypass_domains": "x.test"})
		_ = runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"cache_bypass_domains": ""})
		b, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "cache_bypass_domains.txt"))
		if err == nil && strings.Contains(string(b), "x.test") {
			t.Errorf("clearing the setting left the old ACL in place: %q", b)
		}
	})

	t.Run("squid_settings.env carries the port the operator set", func(t *testing.T) {
		_ = runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"proxy_port": "8128"})
		env, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "squid_settings.env"))
		if err != nil {
			t.Fatalf("squid_settings.env not written: %v", err)
		}
		if !strings.Contains(string(env), "SQUID_PORT=8128") {
			t.Errorf("squid_settings.env = %q, missing SQUID_PORT=8128", env)
		}
	})

	t.Run("invalid JSON is refused", func(t *testing.T) {
		r := withUserContext(httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewReader([]byte("{"))), "admin")
		w := httptest.NewRecorder()
		h.BulkUpdate(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("malformed JSON returned %d", w.Code)
		}
	})
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
