package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type mockDockerClient struct {
	err error
}

func (m *mockDockerClient) KillContainer(name, signal string) error {
	return m.err
}

func (m *mockDockerClient) RestartContainer(name string) error {
	return m.err
}

func TestMaintenanceHandlers_BackupConfig(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg, &mockDockerClient{})

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
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data["proxy_port"] != "3128" {
		t.Errorf("Expected proxy_port 3128, got %s", resp.Data["proxy_port"])
	}
}

func TestMaintenanceHandlers_RestoreConfig(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg, &mockDockerClient{})

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
	db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='proxy_port'").Scan(&val)
	if val != "8080" {
		t.Errorf("Expected 8080, got %s", val)
	}
}

func TestMaintenanceHandlers_DownloadCA(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg, &mockDockerClient{})

	// Test not found
	r := httptest.NewRequest("GET", "/api/security/download-ca", nil)
	w := httptest.NewRecorder()
	h.DownloadCA(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Create dummy cert
	certPath := filepath.Join(cfg.ConfigDir, "ssl_cert.pem")
	os.MkdirAll(cfg.ConfigDir, 0750)
	os.WriteFile(certPath, []byte("dummy cert"), 0644)
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
	h := NewMaintenanceHandlers(db, cfg, &mockDockerClient{})

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
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Status != "error" { // because dummy is missing initially
		t.Errorf("Expected error status for missing cert, got %v", resp.Status)
	}
}

func TestMaintenanceHandlers_ReloadConfig(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg, &mockDockerClient{})

	r := httptest.NewRequest("POST", "/api/maintenance/reload-config", nil)
	w := httptest.NewRecorder()
	h.ReloadConfig(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	time.Sleep(100 * time.Millisecond)
}

func TestMaintenanceHandlers_ReloadDNS(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg, &mockDockerClient{})

	r := httptest.NewRequest("POST", "/api/maintenance/reload-dns", nil)
	w := httptest.NewRecorder()
	h.ReloadDNS(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	time.Sleep(100 * time.Millisecond)
}

func TestMaintenanceHandlers_ClearCache(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg, &mockDockerClient{})

	r := httptest.NewRequest("POST", "/api/maintenance/clear-cache", nil)
	w := httptest.NewRecorder()
	h.ClearCache(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	time.Sleep(100 * time.Millisecond)
}
