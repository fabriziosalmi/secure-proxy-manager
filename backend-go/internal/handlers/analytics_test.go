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
	_, _ = db.Exec("INSERT INTO proxy_logs (timestamp, source_ip, destination, status) VALUES (?, '1.1.1.1', 'http://a.com', '200 OK')", today)

	r := httptest.NewRequest("GET", "/api/traffic/statistics?period=day", nil)
	w := httptest.NewRecorder()
	h.TrafficStats(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

// Regression: a log at a mid-bucket minute within the last hour must be counted
// in the 5-minute hour view (per-minute SQL buckets never matched the 5-min
// label grid, dropping ~all points).
func TestAnalyticsHandlers_TrafficStats_HourBucketing(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	ts := time.Now().UTC().Add(-12 * time.Minute)
	tsStr := ts.Format("2006-01-02 15:04:05")
	for i := 0; i < 3; i++ {
		// unix_timestamp is what the time-window range scan now filters/buckets on
		// (the log tailer always populates it in production).
		_, _ = db.Exec("INSERT INTO proxy_logs (timestamp, unix_timestamp, source_ip, destination, status) VALUES (?, ?, '1.1.1.1', 'http://a.com', '200 OK')", tsStr, ts.Unix())
	}

	r := httptest.NewRequest("GET", "/api/traffic/statistics?period=hour", nil)
	w := httptest.NewRecorder()
	h.TrafficStats(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var resp struct {
		Data struct {
			Inbound []int `json:"inbound"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	sum := 0
	for _, v := range resp.Data.Inbound {
		sum += v
	}
	if sum < 3 {
		t.Errorf("hour view dropped data: inbound sum = %d, want >= 3", sum)
	}
}

func TestAnalyticsHandlers_ClientStats(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	now := time.Now().UTC()
	// Recent client (in the 7-day window) and an old one (60 days ago, outside it).
	_, _ = db.Exec("INSERT INTO proxy_logs (timestamp, unix_timestamp, source_ip, destination) VALUES (?, ?, '1.2.3.4', 'http://a.com')",
		now.Format("2006-01-02 15:04:05"), now.Unix())
	_, _ = db.Exec("INSERT INTO proxy_logs (timestamp, unix_timestamp, source_ip, destination) VALUES (?, ?, '9.9.9.9', 'http://old.com')",
		now.AddDate(0, 0, -60).Format("2006-01-02 15:04:05"), now.AddDate(0, 0, -60).Unix())

	r := httptest.NewRequest("GET", "/api/clients/statistics", nil)
	w := httptest.NewRecorder()
	h.ClientStats(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var resp struct {
		Data struct {
			Clients []struct {
				IPAddress string `json:"ip_address"`
			} `json:"clients"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	var hasRecent, hasOld bool
	for _, c := range resp.Data.Clients {
		if c.IPAddress == "1.2.3.4" {
			hasRecent = true
		}
		if c.IPAddress == "9.9.9.9" {
			hasOld = true
		}
	}
	if !hasRecent {
		t.Error("recent client (in 7-day window) missing from ClientStats")
	}
	if hasOld {
		t.Error("old client (60 days ago) must be excluded by the time-window bound")
	}
}

func TestAnalyticsHandlers_DomainStats(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	now := time.Now().UTC()
	_, _ = db.Exec("INSERT INTO proxy_logs (timestamp, unix_timestamp, destination, status) VALUES (?, ?, 'example.com', '200 OK')",
		now.Format("2006-01-02 15:04:05"), now.Unix())

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

	_, _ = db.Exec("INSERT INTO proxy_logs (timestamp, unix_timestamp, destination, status, blocked) VALUES (datetime('now'), strftime('%s','now'), 'evil.com', '403 Forbidden', 1)")

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

	_, _ = db.Exec("INSERT INTO proxy_logs (timestamp, unix_timestamp, destination) VALUES (datetime('now'), strftime('%s','now'), 'dropbox.com')")

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

	_, _ = db.Exec("INSERT INTO audit_log (username, action) VALUES ('admin', 'test')")

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

	_, _ = db.Exec("INSERT INTO proxy_logs (timestamp, unix_timestamp, destination) VALUES (datetime('now'), strftime('%s','now'), 'malware-site.com')")

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
