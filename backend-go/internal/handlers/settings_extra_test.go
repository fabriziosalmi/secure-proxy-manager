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

func TestSettingsHandlers_Register(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)
	r := chi.NewRouter()
	authMW := func(next http.Handler) http.Handler { return next }
	h.Register(r, authMW)
}

func TestSettingsHandlers_Update_TooLong(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	val := make([]byte, 10001)
	for i := range val {
		val[i] = 'a'
	}
	body, _ := json.Marshal(map[string]string{"value": string(val)})
	
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "test")
	r := httptest.NewRequest("PUT", "/api/settings/test", bytes.NewBuffer(body))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	
	w := httptest.NewRecorder()
	h.Update(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for too long value, got %d", w.Code)
	}
}

func TestSettingsHandlers_Update_InvalidJSON(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	r := httptest.NewRequest("PUT", "/api/settings/test", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()
	h.Update(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestSettingsHandlers_BulkUpdate_SSLBump(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	// Test Enable SSL Bump
	body, _ := json.Marshal(map[string]string{"ssl_bump_enabled": "true"})
	r := httptest.NewRequest("POST", "/api/settings", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.BulkUpdate(w, r)
	
	toggleFile := filepath.Join(cfg.ConfigDir, "ssl_bump_enabled")
	if _, err := os.Stat(toggleFile); os.IsNotExist(err) {
		t.Error("Expected ssl_bump_enabled file to exist")
	}

	// Test Disable SSL Bump
	body, _ = json.Marshal(map[string]string{"ssl_bump_enabled": "false"})
	r = httptest.NewRequest("POST", "/api/settings", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.BulkUpdate(w, r)
	
	if _, err := os.Stat(toggleFile); !os.IsNotExist(err) {
		t.Error("Expected ssl_bump_enabled file to be deleted")
	}
}

func TestSettingsHandlers_BulkUpdate_InvalidJSON(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	r := httptest.NewRequest("POST", "/api/settings", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()
	h.BulkUpdate(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", w.Code)
	}
}
