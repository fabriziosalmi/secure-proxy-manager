package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Values that end up in a file the proxy's root shell used to source. Two of
// them had no validator: bandwidth_limit_per_user_kbps took a newline and any
// assignment after it (PATH=/config removed cat and awk from the generator, so
// dns_nameservers was never written and the DNS blocklists stopped applying),
// and extra_ssl_ports took letters and spaces ("8443 pkill squid" ran pkill).
func TestSettingsRefuseValuesThatWouldReachTheProxyShell(t *testing.T) {
	for key, value := range map[string]string{
		"bandwidth_limit_per_user_kbps": "0\nPATH=/config",
		"extra_ssl_ports":               "8443 pkill squid",
	} {
		t.Run(key, func(t *testing.T) {
			db, _, cfg, cleanup := setupTestDB(t)
			defer cleanup()
			body, _ := json.Marshal(map[string]string{key: value})
			w := httptest.NewRecorder()
			NewSettingsHandlers(db, cfg).BulkUpdate(w, httptest.NewRequest("POST", "/api/settings", bytes.NewReader(body)))
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s=%q was accepted with %d", key, value, w.Code)
			}
		})
	}

	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	body, _ := json.Marshal(map[string]string{"extra_ssl_ports": "8443, 9443", "bandwidth_limit_per_user_kbps": "512"})
	w := httptest.NewRecorder()
	NewSettingsHandlers(db, cfg).BulkUpdate(w, httptest.NewRequest("POST", "/api/settings", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Errorf("valid values were refused: %d %s", w.Code, w.Body.String())
	}
}

// A value already in the database (from an older version, or written past the
// API) must not reach the file either: the writers validate at write time.
func TestBandwidthFileNeverCarriesAnInjectedLine(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.ConfigDir = t.TempDir()
	_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES('bandwidth_limit_per_user_kbps', ?)", "0\nPATH=/config")
	NewSettingsHandlers(db, cfg).writeBandwidthSettings(map[string]string{})
	b, _ := os.ReadFile(filepath.Join(cfg.ConfigDir, "bandwidth_limits.conf"))
	if strings.Contains(string(b), "PATH=") {
		t.Errorf("an injected assignment reached bandwidth_limits.conf:\n%s", b)
	}
}

// Restore checked key names and length only, so a crafted backup stored values
// BulkUpdate refuses: proxy_port="abc", log_retention_days="-5" (which turns off
// log pruning), and the bandwidth injection above.
func TestRestoreAppliesTheSameValueRulesAsTheSettingsAPI(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	backup := map[string]any{
		"backup_version": 2,
		"settings": map[string]string{
			"proxy_port":                    "abc",
			"log_retention_days":            "-5",
			"bandwidth_limit_per_user_kbps": "0\nPATH=/config",
			"cache_size":                    "1234",
		},
	}
	b, _ := json.Marshal(backup)
	w := httptest.NewRecorder()
	NewMaintenanceHandlers(db, cfg).RestoreConfig(w, httptest.NewRequest("POST", "/api/maintenance/restore-config", bytes.NewReader(b)))
	if w.Code != http.StatusOK {
		t.Fatalf("restore = %d: %s", w.Code, w.Body.String())
	}
	get := func(k string) string {
		var v string
		_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name=?", k).Scan(&v)
		return v
	}
	if get("proxy_port") == "abc" || get("log_retention_days") == "-5" || strings.Contains(get("bandwidth_limit_per_user_kbps"), "PATH") {
		t.Errorf("restore stored values the settings API refuses: proxy_port=%q log_retention_days=%q per_user=%q",
			get("proxy_port"), get("log_retention_days"), get("bandwidth_limit_per_user_kbps"))
	}
	if get("cache_size") != "1234" {
		t.Errorf("a valid value was not restored: cache_size=%q", get("cache_size"))
	}
}
