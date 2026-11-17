package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
)

func putSetting(t *testing.T, h *SettingsHandlers, name, value string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"value": value})
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", name)
	r := httptest.NewRequest("PUT", "/api/settings/"+name, bytes.NewBuffer(body))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Update(w, r)
	return w
}

// PUT /api/settings/{name} wrote the database row only, so a toggle set this
// way never reached the marker file the proxy reads: default deny for egress
// answered success and stayed off. It now goes through BulkUpdate's path.
func TestPutSettingWritesTheMarkerTheProxyReads(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)
	marker := filepath.Join(cfg.ConfigDir, "egress_default_deny")
	_ = os.Remove(marker)

	if w := putSetting(t, h, "egress_default_deny", "true"); w.Code != http.StatusOK {
		t.Fatalf("PUT true = %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the marker was not written: %v", err)
	}
	var stored string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='egress_default_deny'").Scan(&stored)
	if stored != "true" {
		t.Errorf("stored = %q", stored)
	}

	if w := putSetting(t, h, "egress_default_deny", "false"); w.Code != http.StatusOK {
		t.Fatalf("PUT false = %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Errorf("the marker survived turning the toggle off: %v", err)
	}
}

// A list setting set by PUT reaches the file its Squid ACL loads, in the form a
// save from the UI writes.
func TestPutSettingWritesTheListArtefact(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)
	if w := putSetting(t, h, "blocked_file_types", "exe"); w.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", w.Code, w.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "blocked_file_types.txt"))
	if err != nil || string(got) != blockedExtensionPattern("exe")+"\n" {
		t.Errorf("blocked_file_types.txt = %q (%v)", got, err)
	}
}

// The route keeps its own contract: a refused value is a 400 with the reason,
// and a secret named with an empty value is cleared, as it always was.
func TestPutSettingRefusesAndClearsAsBefore(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	h := NewSettingsHandlers(db, cfg)
	if w := putSetting(t, h, "auto_refresh_hours", "0"); w.Code != http.StatusBadRequest {
		t.Errorf("an out-of-range value = %d, want 400", w.Code)
	}
	if w := putSetting(t, h, "telegram_bot_token", "123:abc"); w.Code != http.StatusOK {
		t.Fatalf("set secret = %d %s", w.Code, w.Body.String())
	}
	if w := putSetting(t, h, "telegram_bot_token", ""); w.Code != http.StatusOK {
		t.Fatalf("clear secret = %d %s", w.Code, w.Body.String())
	}
	var stored string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='telegram_bot_token'").Scan(&stored)
	if stored != "" {
		t.Errorf("the secret was not cleared: %q", stored)
	}
}

// A time window or a bandwidth value set by PUT, without its toggle, reaches
// the file the proxy reads. The files were rewritten only when the request
// carried enable_time_restrictions or enable_bandwidth_limits, so
// "spm settings set time_restriction_start 09:00" answered "Setting updated"
// and the proxy kept the old window.
func TestPutSettingRewritesTheTimeAndBandwidthFiles(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)
	for _, kv := range [][2]string{
		{"time_restriction_start", "08:00"}, {"time_restriction_end", "18:00"}, {"enable_time_restrictions", "true"},
		{"bandwidth_limit_mbps", "100"}, {"bandwidth_limit_per_user_kbps", "0"}, {"enable_bandwidth_limits", "true"},
	} {
		if w := putSetting(t, h, kv[0], kv[1]); w.Code != http.StatusOK {
			t.Fatalf("PUT %s = %d %s", kv[0], w.Code, w.Body.String())
		}
	}

	for _, c := range []struct{ key, value, file, want string }{
		{"time_restriction_start", "09:00", "time_restrictions.conf", "TIME_START=09:00\nTIME_END=18:00\n"},
		{"time_restriction_end", "17:30", "time_restrictions.conf", "TIME_START=09:00\nTIME_END=17:30\n"},
		{"bandwidth_limit_mbps", "50", "bandwidth_limits.conf", "BW_LIMIT_MBPS=50\nBW_PER_USER_KBPS=0\n"},
		{"bandwidth_limit_per_user_kbps", "512", "bandwidth_limits.conf", "BW_LIMIT_MBPS=50\nBW_PER_USER_KBPS=512\n"},
	} {
		if w := putSetting(t, h, c.key, c.value); w.Code != http.StatusOK {
			t.Fatalf("PUT %s = %d %s", c.key, w.Code, w.Body.String())
		}
		got, err := os.ReadFile(filepath.Join(cfg.ConfigDir, c.file))
		if err != nil || string(got) != c.want {
			t.Errorf("after PUT %s=%s, %s = %q (%v), want %q", c.key, c.value, c.file, got, err, c.want)
		}
	}
}
