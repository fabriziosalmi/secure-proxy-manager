package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnalyticsHandlers_Status_Mocked(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	// Mock Proxy
	proxyTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // Squid returns 400 on direct root access
	}))
	defer proxyTs.Close()
	cfg.ProxyURL = proxyTs.URL

	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})
	r := httptest.NewRequest("GET", "/api/status", nil)
	w := httptest.NewRecorder()
	h.Status(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	data := resp["data"].(map[string]any)
	if data["proxy_status"] != "running" {
		t.Errorf("Expected proxy_status running, got %v", data["proxy_status"])
	}
}

func TestAnalyticsHandlers_WAFProxying(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	// Mock WAF
	wafTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stats":
			fmt.Fprintln(w, `{"rules":100}`)
		case "/categories":
			fmt.Fprintln(w, `{"status":"ok","data":[]}`)
		case "/categories/toggle":
			fmt.Fprintln(w, `{"status":"ok"}`)
		case "/reset":
			fmt.Fprintln(w, `{"status":"ok"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer wafTs.Close()
	cfg.WAFURL = wafTs.URL

	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	// 1. WAFStats (inline in DashboardSummary or separate if added)
	// WAFStats is called from DashboardSummary
	r := httptest.NewRequest("GET", "/api/dashboard/summary", nil)
	w := httptest.NewRecorder()
	h.DashboardSummary(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("DashboardSummary failed: %d", w.Code)
	}

	// 2. WAFCategories
	r = httptest.NewRequest("GET", "/api/waf/categories", nil)
	w = httptest.NewRecorder()
	h.WAFCategories(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("WAFCategories failed: %d", w.Code)
	}

	// 3. WAFCategoryToggle
	body, _ := json.Marshal(map[string]any{"category": "test", "enabled": false})
	r = httptest.NewRequest("POST", "/api/waf/categories/toggle", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.WAFCategoryToggle(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("WAFCategoryToggle failed: %d", w.Code)
	}

	// 4. ResetCounters
	r = httptest.NewRequest("POST", "/api/counters/reset", nil)
	w = httptest.NewRecorder()
	h.ResetCounters(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("ResetCounters failed: %d", w.Code)
	}
}

func TestAnalyticsHandlers_MoreStats(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	// Add some logs
	db.Exec("INSERT INTO proxy_logs (timestamp, source_ip, method, destination, status) VALUES (datetime('now'), '1.1.1.1', 'GET', 'http://dropbox.com/file', 'TCP_MISS/200')")
	db.Exec("INSERT INTO proxy_logs (timestamp, source_ip, method, destination, status) VALUES (datetime('now'), '1.1.1.1', 'POST', 'http://example.com/api', 'TCP_MISS/200')")

	// 1. ShadowIT
	r := httptest.NewRequest("GET", "/api/analytics/shadow-it", nil)
	w := httptest.NewRecorder()
	h.ShadowIT(w, r)
	if w.Code != http.StatusOK { t.Errorf("ShadowIT failed: %d", w.Code) }

	// 2. UserAgents (actually counts methods)
	r = httptest.NewRequest("GET", "/api/analytics/user-agents", nil)
	w = httptest.NewRecorder()
	h.UserAgents(w, r)
	if w.Code != http.StatusOK { t.Errorf("UserAgents failed: %d", w.Code) }

	// 3. FileExtensions
	r = httptest.NewRequest("GET", "/api/analytics/file-extensions", nil)
	w = httptest.NewRecorder()
	h.FileExtensions(w, r)
	if w.Code != http.StatusOK { t.Errorf("FileExtensions failed: %d", w.Code) }

	// 4. TopDomains
	r = httptest.NewRequest("GET", "/api/analytics/top-domains", nil)
	w = httptest.NewRecorder()
	h.TopDomains(w, r)
	if w.Code != http.StatusOK { t.Errorf("TopDomains failed: %d", w.Code) }
}

func TestAnalyticsHandlers_TestRule_Extra(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg, &mockDockerClient{})

	db.Exec("INSERT INTO proxy_logs (timestamp, destination) VALUES (datetime('now'), 'http://malicious.com/payload')")

	// Valid rule
	body, _ := json.Marshal(map[string]any{"regex": "malicious", "hours": 24})
	r := httptest.NewRequest("POST", "/api/waf/test-rule", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.TestRule(w, r)
	if w.Code != http.StatusOK { t.Errorf("TestRule failed: %d", w.Code) }

	// Invalid regex
	body, _ = json.Marshal(map[string]any{"regex": "[invalid", "hours": 24})
	r = httptest.NewRequest("POST", "/api/waf/test-rule", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.TestRule(w, r)
	if w.Code != http.StatusBadRequest { t.Errorf("Expected 400 for invalid regex, got %d", w.Code) }
}
