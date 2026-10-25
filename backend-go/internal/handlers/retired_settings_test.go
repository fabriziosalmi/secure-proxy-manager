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
}
