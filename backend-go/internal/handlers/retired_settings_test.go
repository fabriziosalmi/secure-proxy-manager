package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// A retired setting is treated like the other keys the API does not write
// (internally managed ones): POST /api/settings skips it and saves the rest,
// PUT /api/settings/{name} answers 400, and restore skips it with a reason.
func TestARetiredSettingIsNotWrittenAgain(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)
	count := func(k string) int {
		var n int
		_ = db.QueryRow("SELECT COUNT(*) FROM settings WHERE setting_name=?", k).Scan(&n)
		return n
	}

	w, _ := postSettings(t, h, map[string]string{"tailscale_auth_key": "tskey-auth-secret", "enable_waf": "true", "log_retention_days": "21"})
	if w.Code != http.StatusOK || count("tailscale_auth_key") != 0 || count("enable_waf") != 0 {
		t.Errorf("POST: %d, tailscale_auth_key rows %d, enable_waf rows %d; want 200 and none", w.Code, count("tailscale_auth_key"), count("enable_waf"))
	}
	var kept string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='log_retention_days'").Scan(&kept)
	if kept != "21" {
		t.Error("the rest of the request was not saved")
	}

	r := chi.NewRouter()
	h.Register(r, func(next http.Handler) http.Handler { return next })
	pw := httptest.NewRecorder()
	r.ServeHTTP(pw, httptest.NewRequest("PUT", "/api/settings/block_direct_ip", strings.NewReader(`{"value":"true"}`)))
	if pw.Code != http.StatusBadRequest {
		t.Errorf("PUT a retired key: %d, want 400", pw.Code)
	}

	body, _ := json.Marshal(map[string]any{"config": map[string]string{"ddns_token": "secret", "proxy_port": "3128"}})
	rw := httptest.NewRecorder()
	NewMaintenanceHandlers(db, cfg).RestoreConfig(rw, httptest.NewRequest("POST", "/api/maintenance/restore-config", strings.NewReader(string(body))))
	if count("ddns_token") != 0 || !strings.Contains(rw.Body.String(), "no longer used by this version") {
		t.Errorf("restore: %s", rw.Body.String())
	}

	// Schema version 8 retired settings: allowed_networks, waf_custom_rules, waf_block_threshold.
	for _, k := range []string{"allowed_networks", "waf_custom_rules", "waf_block_threshold"} {
		pw8 := httptest.NewRecorder()
		r.ServeHTTP(pw8, httptest.NewRequest("PUT", "/api/settings/"+k, strings.NewReader(`{"value":"x"}`)))
		if pw8.Code != http.StatusBadRequest {
			t.Errorf("PUT /api/settings/%s = %d, want 400", k, pw8.Code)
		}
	}

	body8, _ := json.Marshal(map[string]any{
		"config": map[string]string{
			"allowed_networks":    "10.0.0.0/8",
			"waf_custom_rules":    "rule1",
			"waf_block_threshold": "80",
			"proxy_port":          "3128",
		},
	})
	rw8 := httptest.NewRecorder()
	NewMaintenanceHandlers(db, cfg).RestoreConfig(rw8, httptest.NewRequest("POST", "/api/maintenance/restore-config", strings.NewReader(string(body8))))
	for _, k := range []string{"allowed_networks", "waf_custom_rules", "waf_block_threshold"} {
		if count(k) != 0 {
			t.Errorf("restore wrote retired key %s", k)
		}
		if !strings.Contains(rw8.Body.String(), k) {
			t.Errorf("restore response did not list %s in skipped_settings: %s", k, rw8.Body.String())
		}
	}
}
