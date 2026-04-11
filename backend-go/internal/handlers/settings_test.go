package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestSettingsHandlers_GetAll(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	r := httptest.NewRequest("GET", "/api/settings", nil)
	w := httptest.NewRecorder()
	h.GetAll(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp struct {
		Status string `json:"status"`
		Data   []any  `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Status != "success" {
		t.Errorf("Expected success status, got %v", resp.Status)
	}
	if len(resp.Data) == 0 {
		t.Error("Expected settings data, got empty")
	}
}

func TestSettingsHandlers_Update(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	// Mock chi URL param
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "proxy_port")

	body, _ := json.Marshal(map[string]string{"value": "8080"})
	r := httptest.NewRequest("PUT", "/api/settings/proxy_port", bytes.NewBuffer(body))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Update(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var val string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='proxy_port'").Scan(&val)
	if val != "8080" {
		t.Errorf("Expected 8080, got %s", val)
	}
}

func TestSettingsHandlers_BulkUpdate(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	body, _ := json.Marshal(map[string]string{
		"proxy_port": "9090",
		"cache_size": "2000",
	})
	r := httptest.NewRequest("POST", "/api/settings", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.BulkUpdate(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var val string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='proxy_port'").Scan(&val)
	if val != "9090" {
		t.Errorf("Expected 9090, got %s", val)
	}
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='cache_size'").Scan(&val)
	if val != "2000" {
		t.Errorf("Expected 2000, got %s", val)
	}
}
