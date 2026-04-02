package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBlacklistHandlers_ErrorCases(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewBlacklistHandlers(db, cfg)

	// Invalid IP
	body, _ := json.Marshal(map[string]string{"ip": "invalid-ip"})
	r := httptest.NewRequest("POST", "/api/blacklists/ip", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.AddIP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid IP, got %d", w.Code)
	}

	// Empty IP
	body, _ = json.Marshal(map[string]string{"ip": ""})
	r = httptest.NewRequest("POST", "/api/blacklists/ip", bytes.NewReader(body))
	w = httptest.NewRecorder()
	h.AddIP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for empty IP, got %d", w.Code)
	}

	// Duplicate IP
	body, _ = json.Marshal(map[string]string{"ip": "1.2.3.4"})
	r = httptest.NewRequest("POST", "/api/blacklists/ip", bytes.NewReader(body))
	w = httptest.NewRecorder()
	h.AddIP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for first add, got %d", w.Code)
	}
	
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/blacklists/ip", bytes.NewReader(body))
	h.AddIP(w, r)
	if w.Code != http.StatusBadRequest {
	    t.Errorf("Expected 400 for duplicate add, got %d", w.Code)
	}
	// Give time for propagate goroutine to finish (affects cleanup)
	time.Sleep(100 * time.Millisecond)
}

func TestHelper_BulkDelete_Errors(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	
	// Create the handler using the helper from blacklists.go
	h := bulkDeleteHandler(db, "ip_blacklist", cfg)

	// Invalid JSON
	r := httptest.NewRequest("POST", "/api/blacklists/ip/bulk-delete", bytes.NewReader([]byte("invalid-json")))
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", w.Code)
	}

	// Empty list
	body, _ := json.Marshal(map[string]any{"ips": []string{}})
	r = httptest.NewRequest("POST", "/api/blacklists/ip/bulk-delete", bytes.NewReader(body))
	w = httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for empty list body, got %d", w.Code)
	}
}
