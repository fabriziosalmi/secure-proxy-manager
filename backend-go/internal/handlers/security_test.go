package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
	"github.com/go-chi/chi/v5"
)

func TestSecurityHandlers_ReceiveAlert(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	
	notify := NewNotifyQueue(db, "0000000000000000000000000000000000000000000000000000000000000000")
	h := NewSecurityHandlers(db, nil, nil, notify)

	alert := models.InternalAlert{
		EventType: "test_event",
		Message:    "test message",
		Level:      "info",
		Details:    map[string]any{"foo": "bar"},
	}
	body, _ := json.Marshal(alert)
	r := httptest.NewRequest("POST", "/api/internal/alert", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.ReceiveAlert(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	// Note: We don't wait for the notification worker to finish in this simple test
}

func TestSecurityHandlers_GetRateLimits(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSecurityHandlers(db, svc, cfg, nil)

	r := httptest.NewRequest("GET", "/api/security/rate-limits", nil)
	w := httptest.NewRecorder()
	h.GetRateLimits(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestSecurityHandlers_ClearRateLimit(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSecurityHandlers(db, svc, cfg, nil)

	svc.Authenticate(httptest.NewRequest("GET", "/", nil)) // adds an attempt? no, fails because no auth

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("ip", "1.1.1.1")
	r := httptest.NewRequest("DELETE", "/api/security/rate-limits/1.1.1.1", nil)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	
	// Should be 404 because no active rate limit for 1.1.1.1
	h.ClearRateLimit(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestSecurityHandlers_Score(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSecurityHandlers(db, nil, nil, nil)

	// Set some settings
	db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES ('enable_waf', 'true')")
	db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES ('enable_ip_blacklist', 'true')")

	r := httptest.NewRequest("GET", "/api/security/score", nil)
	w := httptest.NewRecorder()
	h.Score(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	data := resp["data"].(map[string]any)
	score := data["score"].(float64)
	if score < 40 { // 25 (WAF) + 15 (IP Blacklist) = 40
		t.Errorf("Expected score at least 40, got %f", score)
	}
}

func TestSecurityHandlers_CVECheck(t *testing.T) {
	h := &SecurityHandlers{}
	r := httptest.NewRequest("GET", "/api/security/cve", nil)
	w := httptest.NewRecorder()
	h.CVECheck(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}
