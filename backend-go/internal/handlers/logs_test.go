package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

func TestLogHandlers_GetLogs(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewLogHandlers(db)

	// Add test logs
	db.Exec("INSERT INTO proxy_logs (timestamp, source_ip, method, destination, status, bytes) VALUES (datetime('now'), '1.1.1.1', 'GET', 'http://example.com', '200 OK', 123)")

	r := httptest.NewRequest("GET", "/api/logs", nil)
	w := httptest.NewRecorder()
	h.GetLogs(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestLogHandlers_GDPR(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewLogHandlers(db)

	// Enable GDPR mode
	db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES ('gdpr_mode', 'true')")
	db.Exec("INSERT INTO proxy_logs (timestamp, source_ip, method, destination, status, bytes) VALUES (datetime('now'), '192.168.1.5', 'GET', 'http://example.com', '200 OK', 123)")

	r := httptest.NewRequest("GET", "/api/logs", nil)
	w := httptest.NewRecorder()
	h.GetLogs(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	// Check if IP is masked (maskIP masks last octet for IPv4)
	if !strings.Contains(w.Body.String(), "192.168.1.x") {
		t.Errorf("Expected masked IP 192.168.1.x, got body: %s", w.Body.String())
	}
}

func TestLogHandlers_Stats(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewLogHandlers(db)

	db.Exec("INSERT INTO proxy_logs (timestamp, source_ip, method, destination, status, bytes) VALUES (datetime('now'), '1.1.1.1', 'GET', 'http://example.com', '403 Forbidden', 0)")

	r := httptest.NewRequest("GET", "/api/logs/stats", nil)
	w := httptest.NewRecorder()
	h.Stats(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestLogHandlers_Clear(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewLogHandlers(db)

	db.Exec("INSERT INTO proxy_logs (source_ip) VALUES ('1.1.1.1')")
	
	r := httptest.NewRequest("POST", "/api/logs/clear", nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.CtxUsername, "admin"))
	w := httptest.NewRecorder()
	h.Clear(w, r)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}
