package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAnalyticsHandlers_Status(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	r := httptest.NewRequest("GET", "/api/status", nil)
	w := httptest.NewRecorder()
	h.Status(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestAnalyticsHandlers_TrafficStats(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	// Add some logs in the past 24h
	today := time.Now().Format("2006-01-02 15:04:05")
	db.Exec("INSERT INTO proxy_logs (timestamp, source_ip, destination, status) VALUES (?, '1.1.1.1', 'http://a.com', '200 OK')", today)

	r := httptest.NewRequest("GET", "/api/traffic/statistics?period=day", nil)
	w := httptest.NewRecorder()
	h.TrafficStats(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestAnalyticsHandlers_ClientStats(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	db.Exec("INSERT INTO proxy_logs (source_ip, destination) VALUES ('1.2.3.4', 'http://a.com')")

	r := httptest.NewRequest("GET", "/api/clients/statistics", nil)
	w := httptest.NewRecorder()
	h.ClientStats(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestAnalyticsHandlers_DomainStats(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	db.Exec("INSERT INTO proxy_logs (destination, status) VALUES ('example.com', '200 OK')")

	r := httptest.NewRequest("GET", "/api/domains/statistics", nil)
	w := httptest.NewRecorder()
	h.DomainStats(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestAnalyticsHandlers_DashboardSummary(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	db.Exec("INSERT INTO proxy_logs (timestamp, destination, status) VALUES (datetime('now'), 'evil.com', '403 Forbidden')")

	r := httptest.NewRequest("GET", "/api/dashboard/summary", nil)
	w := httptest.NewRecorder()
	h.DashboardSummary(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestAnalyticsHandlers_ShadowIT(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	db.Exec("INSERT INTO proxy_logs (timestamp, destination) VALUES (datetime('now'), 'dropbox.com')")

	r := httptest.NewRequest("GET", "/api/analytics/shadow-it", nil)
	w := httptest.NewRecorder()
	h.ShadowIT(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestAnalyticsHandlers_AuditLog(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	db.Exec("INSERT INTO audit_log (username, action) VALUES ('admin', 'test')")

	r := httptest.NewRequest("GET", "/api/audit-log", nil)
	w := httptest.NewRecorder()
	h.AuditLog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestAnalyticsHandlers_TestRule(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	db.Exec("INSERT INTO proxy_logs (timestamp, destination) VALUES (datetime('now'), 'malware-site.com')")

	req := struct {
		Regex string `json:"regex"`
		Hours int    `json:"hours"`
	}{
		Regex: "malware",
		Hours: 24,
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/api/waf/test-rule", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.TestRule(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}
