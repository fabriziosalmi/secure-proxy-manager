package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogs_Timeline(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewLogHandlers(db)

	r := httptest.NewRequest("GET", "/api/logs/timeline?hours=24", nil)
	w := httptest.NewRecorder()
	h.Timeline(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if resp["data"] == nil {
		t.Errorf("Expected valid json array in 'data', got nil")
	}

	// invalid hours
	r = httptest.NewRequest("GET", "/api/logs/timeline?hours=-1", nil)
	w = httptest.NewRecorder()
	h.Timeline(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestLogs_ClearOld(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewLogHandlers(db)

	r := httptest.NewRequest("DELETE", "/api/logs/old?days=30", nil)
	w := httptest.NewRecorder()
	h.ClearOld(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// invalid days
	r = httptest.NewRequest("DELETE", "/api/logs/old?days=-1", nil)
	w = httptest.NewRecorder()
	h.ClearOld(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestHelpers(t *testing.T) {
	// queryInt coverage via helper
	r := httptest.NewRequest("GET", "/path?valid=123&invalid=abc", nil)
	if queryInt(r, "valid", 10) != 123 {
		t.Errorf("Expected 123 from queryInt")
	}
	if queryInt(r, "invalid", 10) != 10 {
		t.Errorf("Expected fallback 10 from queryInt")
	}
	if queryInt(r, "missing", 10) != 10 {
		t.Errorf("Expected fallback 10 from missing queryInt")
	}
}
