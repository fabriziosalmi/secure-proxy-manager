package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func allSettings(t *testing.T, h *SettingsHandlers) map[string]string {
	t.Helper()
	rows, err := h.db.Query("SELECT setting_name, setting_value FROM settings")
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[k] = v
	}
	return out
}

func getAllBody(t *testing.T, h *SettingsHandlers) string {
	t.Helper()
	w := httptest.NewRecorder()
	h.GetAll(w, httptest.NewRequest("GET", "/api/settings", nil))
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byName := map[string]map[string]any{}
	for _, row := range resp.Data {
		byName[row["setting_name"].(string)] = row
	}
	b, _ := json.Marshal(byName)
	return string(b)
}

// The Settings page now offers Backup and Restore over these two endpoints,
// so a backup taken and restored must give back the settings as they were,
// secrets included, and the proxy files they drive.
func TestBackupThenRestoreGivesTheSameSettings(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	sh := NewSettingsHandlers(db, cfg)
	mh := NewMaintenanceHandlers(db, cfg)

	if w, _ := bulkUpdate(t, sh, "", map[string]string{
		"enable_safesearch":        "true",
		"enable_content_filtering": "true",
		"blocked_file_types":       "exe,msi",
		"log_retention_days":       "14",
		"gotify_token":             "token-before",
	}); w.Code != http.StatusOK {
		t.Fatalf("seed: %d %s", w.Code, w.Body.String())
	}
	before := allSettings(t, sh)
	beforeAPI := getAllBody(t, sh)

	w := httptest.NewRecorder()
	mh.BackupConfig(w, httptest.NewRequest("GET", "/api/maintenance/backup-config", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("backup: %d", w.Code)
	}
	var backup struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&backup); err != nil {
		t.Fatalf("decode backup: %v", err)
	}

	// Change everything the backup holds, as an operator would before
	// regretting it.
	if w, _ := bulkUpdate(t, sh, "", map[string]string{
		"enable_safesearch":  "false",
		"blocked_file_types": "zip",
		"log_retention_days": "90",
		"gotify_token":       "token-after",
	}); w.Code != http.StatusOK {
		t.Fatalf("change: %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.ConfigDir, "safesearch_enabled")); !os.IsNotExist(err) {
		t.Fatalf("precondition: the SafeSearch marker should be gone after turning it off")
	}

	payload, _ := json.Marshal(backup.Data)
	w2 := httptest.NewRecorder()
	mh.RestoreConfig(w2, httptest.NewRequest("POST", "/api/maintenance/restore-config", bytes.NewReader(payload)))
	if w2.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w2.Code, w2.Body.String())
	}

	if after := allSettings(t, sh); !reflect.DeepEqual(before, after) {
		for k, v := range before {
			if after[k] != v {
				t.Errorf("%s: before %q, after restore %q", k, v, after[k])
			}
		}
		t.Fatal("the restored settings differ from the backed-up ones")
	}
	if afterAPI := getAllBody(t, sh); afterAPI != beforeAPI {
		t.Errorf("GET /api/settings differs after the round trip:\nbefore %s\nafter  %s", beforeAPI, afterAPI)
	}

	// The proxy files follow the restored settings, not the later change.
	if _, err := os.Stat(filepath.Join(cfg.ConfigDir, "safesearch_enabled")); err != nil {
		t.Errorf("the restored SafeSearch toggle did not reach its marker file: %v", err)
	}
	types, _ := os.ReadFile(filepath.Join(cfg.ConfigDir, "blocked_file_types.txt"))
	if string(types) != "\\.exe(\\?.*)?$\n\\.msi(\\?.*)?$\n" {
		t.Errorf("blocked_file_types.txt holds %q, want the restored list", types)
	}

	// The answer says what it did not restore, and why.
	var resp struct {
		RestoredSettings int `json:"restored_settings"`
		SkippedSettings  []struct {
			Key    string `json:"key"`
			Reason string `json:"reason"`
		} `json:"skipped_settings"`
		FailedFiles []string `json:"failed_files"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode restore: %v", err)
	}
	if resp.RestoredSettings == 0 {
		t.Error("restored_settings is 0")
	}
	found := false
	for _, s := range resp.SkippedSettings {
		if s.Key == "default_password_changed" {
			found = true
			if s.Reason == "" {
				t.Error("a skipped setting carries no reason")
			}
		}
	}
	if !found {
		t.Errorf("default_password_changed is in the backup and is never restored, so it must be listed as skipped: %+v", resp.SkippedSettings)
	}
	if len(resp.FailedFiles) != 0 {
		t.Errorf("no file should fail in a writable config dir: %v", resp.FailedFiles)
	}
}

// A value the settings API would refuse is skipped with the validator's
// message, so the page can show why.
func TestRestoreNamesTheReasonForASkippedValue(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	mh := NewMaintenanceHandlers(db, cfg)

	payload, _ := json.Marshal(map[string]any{"backup_version": 2, "settings": map[string]string{"proxy_port": "abc", "log_retention_days": "7"}})
	w := httptest.NewRecorder()
	mh.RestoreConfig(w, httptest.NewRequest("POST", "/api/maintenance/restore-config", bytes.NewReader(payload)))
	if w.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		SkippedSettings []skippedSetting `json:"skipped_settings"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	want := []skippedSetting{{Key: "proxy_port", Reason: "must be a port between 1 and 65535"}}
	if !reflect.DeepEqual(resp.SkippedSettings, want) {
		t.Errorf("skipped_settings = %+v, want %+v", resp.SkippedSettings, want)
	}
}
