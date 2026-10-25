package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func postSettings(t *testing.T, h *SettingsHandlers, body map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	h.BulkUpdate(w, httptest.NewRequest("POST", "/api/settings", strings.NewReader(string(b))))
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp
}

// Every refused field comes back at once, by key, and nothing is stored.
func TestBulkUpdateReturnsEveryFieldError(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)
	w, resp := postSettings(t, h, map[string]string{
		"cache_size":           "12345678",
		"memory_cache":         "0",
		"auto_refresh_hours":   "200",
		"blocked_file_types":   "exe, *",
		"cache_bypass_domains": "bank.example.com, not a domain",
		"webhook_url":          "file:///etc/passwd",
		"log_retention_days":   "15",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", w.Code, w.Body.String())
	}
	errs, _ := resp["errors"].(map[string]any)
	want := map[string]string{
		"cache_size":           "from 1 to 9999999",
		"memory_cache":         "from 1 to 999999",
		"auto_refresh_hours":   "from 1 to 168",
		"blocked_file_types":   `"*" is not a file extension`,
		"cache_bypass_domains": `"not a domain" is not a domain name`,
		"webhook_url":          "http or https URL",
	}
	if len(errs) != len(want) {
		t.Errorf("errors = %v, want %d keys", errs, len(want))
	}
	for k, sub := range want {
		if msg, _ := errs[k].(string); !strings.Contains(msg, sub) {
			t.Errorf("errors[%s] = %q, want it to contain %q", k, msg, sub)
		}
	}
	// detail keeps its shape for callers that read only it.
	if d, _ := resp["detail"].(string); d != "auto_refresh_hours: "+errs["auto_refresh_hours"].(string) {
		t.Errorf("detail = %q, want the first key in order", d)
	}
	var stored string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='log_retention_days'").Scan(&stored)
	if stored == "15" {
		t.Error("a valid key of a refused request was stored")
	}
}

func TestBulkUpdateChecksValuesThatDependOnEachOther(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	w, resp := postSettings(t, h, map[string]string{
		"enable_time_restrictions": "true", "time_restriction_start": "18:00", "time_restriction_end": "08:00",
	})
	if w.Code != http.StatusBadRequest || resp["errors"].(map[string]any)["time_restriction_end"] != "must be later than the start time" {
		t.Errorf("a window ending before it starts: %d %v", w.Code, resp)
	}
	// The same window with the switch off is not enforced, so it is accepted.
	if w, _ := postSettings(t, h, map[string]string{
		"enable_time_restrictions": "false", "time_restriction_start": "18:00", "time_restriction_end": "08:00",
	}); w.Code != http.StatusOK {
		t.Errorf("a window with the switch off: %d", w.Code)
	}
	// Turning the switch on later is checked against the stored window.
	if w, _ := postSettings(t, h, map[string]string{"enable_time_restrictions": "true"}); w.Code != http.StatusBadRequest {
		t.Errorf("switching on over a stored backwards window: %d, want 400", w.Code)
	}

	w, resp = postSettings(t, h, map[string]string{"enable_content_filtering": "true", "blocked_file_types": " , "})
	if w.Code != http.StatusBadRequest || !strings.Contains(resp["errors"].(map[string]any)["blocked_file_types"].(string), "at least one extension") {
		t.Errorf("content filtering with no extension: %d %v", w.Code, resp)
	}
	// A save of another section is not blocked by a problem stored elsewhere.
	if w, _ := postSettings(t, h, map[string]string{"log_retention_days": "20"}); w.Code != http.StatusOK {
		t.Errorf("an unrelated save: %d", w.Code)
	}
}

// A restored backup carries secrets as the encrypted column; the URL rule
// cannot read them and must not refuse them.
func TestAnEncryptedSecretIsNotCheckedAsAURL(t *testing.T) {
	if err := validateSettingValue("webhook_url", "enc::00112233"); err != nil {
		t.Errorf("an encrypted webhook_url was refused: %v", err)
	}
	if err := validateSettingValue("webhook_url", "ftp://x"); err == nil {
		t.Error("a plaintext ftp URL was accepted")
	}
}

func wafStub(t *testing.T, toggleStatus int, heuristics string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/heuristics/toggle":
			w.WriteHeader(toggleStatus)
		case "/heuristics":
			if toggleStatus != http.StatusOK {
				w.WriteHeader(toggleStatus)
				return
			}
			_, _ = w.Write([]byte(heuristics))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The save reports what the WAF did with the toggles; it used to say
// "Settings updated" while the WAF refused every one.
func TestBulkUpdateReportsTheWAFPush(t *testing.T) {
	for _, c := range []struct {
		name, token string
		status      int
		pushed      int
		reason      string
	}{
		{"accepted", "tok", http.StatusOK, 1, ""},
		{"no token", "", http.StatusForbidden, 0, "INTERNAL_ALERT_TOKEN is not set"},
		{"different token", "tok", http.StatusForbidden, 0, "must be the same on the waf and backend"},
	} {
		t.Run(c.name, func(t *testing.T) {
			db, _, cfg, cleanup := setupTestDB(t)
			defer cleanup()
			cfg.WAFURL = wafStub(t, c.status, "").URL
			cfg.AlertToken = c.token
			w, resp := postSettings(t, NewSettingsHandlers(db, cfg), map[string]string{"waf_h_sequence": "true", "log_retention_days": "30"})
			if w.Code != http.StatusOK {
				t.Fatalf("status %d", w.Code)
			}
			raw, _ := json.Marshal(resp["data"].(map[string]any)["waf"])
			var waf wafPushResult
			_ = json.Unmarshal(raw, &waf)
			if len(waf.Pushed) != c.pushed {
				t.Errorf("pushed = %v, want %d", waf.Pushed, c.pushed)
			}
			if c.reason != "" && (len(waf.Failed) != 1 || waf.Failed[0].Key != "waf_h_sequence" || !strings.Contains(waf.Failed[0].Reason, c.reason)) {
				t.Errorf("failed = %+v, want waf_h_sequence with %q", waf.Failed, c.reason)
			}
		})
	}
	// A save without a heuristic says nothing about the WAF.
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	_, resp := postSettings(t, NewSettingsHandlers(db, cfg), map[string]string{"log_retention_days": "30"})
	if _, ok := resp["data"].(map[string]any)["waf"]; ok {
		t.Error("a save with no heuristic reports a WAF push")
	}
}

func TestWAFHeuristicsReportsTheRunningState(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.WAFURL = wafStub(t, http.StatusOK, `{"status":"ok","data":{"waf_h_entropy":true,"waf_h_sequence":false,"other":true}}`).URL
	cfg.AlertToken = "tok"
	w := httptest.NewRecorder()
	NewSettingsHandlers(db, cfg).WAFHeuristics(w, httptest.NewRequest("GET", "/api/waf/heuristics", nil))
	var resp struct {
		Data struct {
			Available bool            `json:"available"`
			Running   map[string]bool `json:"running"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Data.Available || len(resp.Data.Running) != 2 || !resp.Data.Running["waf_h_entropy"] || resp.Data.Running["waf_h_sequence"] {
		t.Errorf("response = %s", w.Body.String())
	}

	cfg.WAFURL = wafStub(t, http.StatusForbidden, "").URL
	cfg.AlertToken = ""
	w = httptest.NewRecorder()
	NewSettingsHandlers(db, cfg).WAFHeuristics(w, httptest.NewRequest("GET", "/api/waf/heuristics", nil))
	if !strings.Contains(w.Body.String(), `"available":false`) || !strings.Contains(w.Body.String(), "INTERNAL_ALERT_TOKEN is not set") {
		t.Errorf("without a token: %s", w.Body.String())
	}
}

// A list setting the database holds reaches the proxy's file at startup,
// even though no save wrote it.
func TestSyncListArtefactsWritesWhatTheDatabaseHolds(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES('blocked_file_types','exe, MSI')")
	_ = os.Remove(filepath.Join(cfg.ConfigDir, "blocked_file_types.txt"))
	h := NewSettingsHandlers(db, cfg)
	changed := h.SyncListArtefacts()
	got, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "blocked_file_types.txt"))
	if err != nil || string(got) != "\\.exe$\n\\.msi$\n" {
		t.Fatalf("blocked_file_types.txt = %q (%v)", got, err)
	}
	if len(changed) == 0 {
		t.Error("a written file is not reported")
	}
	if _, err := os.Stat(filepath.Join(cfg.ConfigDir, ".reload-squid")); err != nil {
		t.Error("the proxy was not asked to reload after the file changed")
	}
	// A second start finds the file in line and changes nothing.
	if again := h.SyncListArtefacts(); len(again) != 0 {
		t.Errorf("second start rewrote %v", again)
	}
}
