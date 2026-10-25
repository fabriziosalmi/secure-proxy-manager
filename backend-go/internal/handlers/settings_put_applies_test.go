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
