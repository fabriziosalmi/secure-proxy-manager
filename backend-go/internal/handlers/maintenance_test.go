package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMaintenanceHandlers_BackupConfig(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	r := httptest.NewRequest("GET", "/api/maintenance/backup-config", nil)
	w := httptest.NewRecorder()
	h.BackupConfig(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var resp struct {
		Status string            `json:"status"`
		Data   map[string]string `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data["proxy_port"] != "3128" {
		t.Errorf("Expected proxy_port 3128, got %s", resp.Data["proxy_port"])
	}
}

func TestMaintenanceHandlers_RestoreConfig(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	body, _ := json.Marshal(map[string]any{
		"config": map[string]string{"proxy_port": "8080"},
	})
	r := httptest.NewRequest("POST", "/api/maintenance/restore-config", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.RestoreConfig(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var val string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='proxy_port'").Scan(&val)
	if val != "8080" {
		t.Errorf("Expected 8080, got %s", val)
	}
}

func TestMaintenanceHandlers_DownloadCA(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	// Test not found
	r := httptest.NewRequest("GET", "/api/security/download-ca", nil)
	w := httptest.NewRecorder()
	h.DownloadCA(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Create dummy cert
	certPath := filepath.Join(cfg.ConfigDir, "ssl_cert.pem")
	_ = os.MkdirAll(cfg.ConfigDir, 0750)
	_ = os.WriteFile(certPath, []byte("dummy cert"), 0644)
	defer os.Remove(certPath)

	w = httptest.NewRecorder()
	h.DownloadCA(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/x-x509-ca-cert" {
		t.Errorf("Expected cert content type, got %s", w.Header().Get("Content-Type"))
	}
}

func TestMaintenanceHandlers_CheckCertSecurity(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	r := httptest.NewRequest("GET", "/api/maintenance/check-cert-security", nil)
	w := httptest.NewRecorder()
	h.CheckCertSecurity(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var resp struct {
		Status string `json:"status"`
		Data   struct {
			Issues []string `json:"issues"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Status != "error" { // because dummy is missing initially
		t.Errorf("Expected error status for missing cert, got %v", resp.Status)
	}
}

// assertTrigger fails unless name exists in cfg.ConfigDir and holds a plausible
// unix timestamp. The trigger file IS the observable effect of these handlers —
// the proxy watchdog polls its mtime — so asserting only on the 200 would let
// the write be deleted outright without a test noticing, since every one of
// these handlers reports success whether or not the write succeeded.
func assertTrigger(t *testing.T, dir, name string) {
	t.Helper()
	path := filepath.Join(dir, name)
	body, err := os.ReadFile(path) // #nosec G304 — test-controlled temp dir
	if err != nil {
		t.Fatalf("trigger %s was not written: %v", name, err)
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		t.Fatalf("trigger %s: want a unix timestamp, got %q", name, body)
	}
	if delta := time.Since(time.Unix(ts, 0)); delta < 0 || delta > time.Minute {
		t.Errorf("trigger %s: timestamp %d is %v away from now", name, ts, delta)
	}
}

func TestMaintenanceHandlers_ReloadConfig(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	r := httptest.NewRequest("POST", "/api/maintenance/reload-config", nil)
	w := httptest.NewRecorder()
	h.ReloadConfig(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	assertTrigger(t, cfg.ConfigDir, ".reload-squid")

	// A second call must re-trigger: the watchdog compares mtime, so an
	// unchanged file would be a silently ignored reload.
	before, err := os.Stat(filepath.Join(cfg.ConfigDir, ".reload-squid"))
	if err != nil {
		t.Fatalf("stat trigger: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	h.ReloadConfig(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/maintenance/reload-config", nil))
	after, err := os.Stat(filepath.Join(cfg.ConfigDir, ".reload-squid"))
	if err != nil {
		t.Fatalf("stat trigger after second reload: %v", err)
	}
	if !after.ModTime().After(before.ModTime()) {
		t.Errorf("second reload did not advance the trigger mtime (%v -> %v)", before.ModTime(), after.ModTime())
	}

	// ReloadConfig also exports the blacklists before signalling.
	if _, err := os.Stat(filepath.Join(cfg.ConfigDir, "ip_blacklist.txt")); err != nil {
		t.Errorf("reload did not export ip_blacklist.txt: %v", err)
	}
}

func TestMaintenanceHandlers_ReloadDNS(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	if _, err := db.Exec("INSERT INTO domain_blacklist (domain) VALUES (?)", "blocked.example"); err != nil {
		t.Fatalf("seed domain_blacklist: %v", err)
	}

	r := httptest.NewRequest("POST", "/api/maintenance/reload-dns", nil)
	w := httptest.NewRecorder()
	h.ReloadDNS(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	assertTrigger(t, cfg.ConfigDir, ".reload-dns")

	// The seeded domain must reach the exported file the DNS sinkhole reads,
	// and the reported count must match what was exported.
	exported, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "domain_blacklist.txt")) // #nosec G304
	if err != nil {
		t.Fatalf("domain_blacklist.txt was not exported: %v", err)
	}
	if !strings.Contains(string(exported), "blocked.example") {
		t.Errorf("exported blacklist is missing the seeded domain: %q", exported)
	}
	var resp struct {
		Data struct {
			Domains int `json:"domains"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data.Domains != 1 {
		t.Errorf("Expected 1 domain reported, got %d", resp.Data.Domains)
	}
}

func TestMaintenanceHandlers_ClearCache(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	r := httptest.NewRequest("POST", "/api/maintenance/clear-cache", nil)
	w := httptest.NewRecorder()
	h.ClearCache(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	assertTrigger(t, cfg.ConfigDir, ".clear-cache")
}
