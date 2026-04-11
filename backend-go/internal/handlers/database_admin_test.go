package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDatabaseHandlers_Size(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewDatabaseHandlers(db)

	r := httptest.NewRequest("GET", "/api/database/size", nil)
	w := httptest.NewRecorder()
	h.Size(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if _, ok := resp.Data["size_bytes"]; !ok {
		t.Error("Expected size_bytes in data field")
	}
}

func TestDatabaseHandlers_Optimize(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewDatabaseHandlers(db)

	r := httptest.NewRequest("POST", "/api/database/optimize", nil)
	w := httptest.NewRecorder()
	h.Optimize(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestDatabaseHandlers_Stats(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewDatabaseHandlers(db)

	r := httptest.NewRequest("GET", "/api/database/stats", nil)
	w := httptest.NewRecorder()
	h.Stats(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestDatabaseHandlers_Export(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewDatabaseHandlers(db)

	r := httptest.NewRequest("GET", "/api/database/export", nil)
	w := httptest.NewRecorder()
	h.Export(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected application/json, got %s", w.Header().Get("Content-Type"))
	}
}

func TestDatabaseHandlers_Reset(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewDatabaseHandlers(db)

	// Add some dummy data
	_, _ = db.Exec("INSERT INTO ip_blacklist (ip) VALUES ('1.1.1.1')")

	r := httptest.NewRequest("POST", "/api/database/reset", nil)
	w := httptest.NewRecorder()
	h.Reset(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 records after reset, got %d", count)
	}
}
