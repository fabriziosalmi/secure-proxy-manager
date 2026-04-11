package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
	"github.com/go-chi/chi/v5"
	"time"
)

func TestBlacklistHandlers_List(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()

	// Add test data
	_, _ = db.Exec("INSERT INTO ip_blacklist (ip, description) VALUES (?,?)", "1.1.1.1", "test ip")
	_, _ = db.Exec("INSERT INTO ip_blacklist (ip, description) VALUES (?,?)", "2.2.2.2", "other ip")

	handler := listHandler(db, "ip_blacklist", "ip")
	
	// Basic list
	r := httptest.NewRequest("GET", "/api/ip-blacklist", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Search
	r = httptest.NewRequest("GET", "/api/ip-blacklist?search=other", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	data := resp["data"].([]any)
	if len(data) != 1 {
		t.Errorf("Expected 1 result for search, got %d", len(data))
	}
}

func TestBlacklistHandlers_AddIP(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewBlacklistHandlers(db, cfg)

	item := models.IPListItem{IP: "10.10.10.10", Description: "New IP"}
	body, _ := json.Marshal(item)
	r := httptest.NewRequest("POST", "/api/ip-blacklist", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.AddIP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist WHERE ip='10.10.10.10'").Scan(&count)
	if count != 1 {
		t.Error("IP not found in database")
	}
	time.Sleep(100 * time.Millisecond)
}

func TestBlacklistHandlers_Delete(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	_, _ = db.Exec("INSERT INTO ip_blacklist (ip) VALUES (?)", "5.5.5.5")
	var id int64
	_ = db.QueryRow("SELECT id FROM ip_blacklist WHERE ip='5.5.5.5'").Scan(&id)

	handler := deleteByIDHandler(db, "ip_blacklist", cfg)
	
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprintf("%d", id))
	r := httptest.NewRequest("DELETE", "/api/ip-blacklist/"+fmt.Sprintf("%d", id), nil)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist WHERE id=?", id).Scan(&count)
	if count != 0 {
		t.Error("Entry still in database after delete")
	}
	time.Sleep(100 * time.Millisecond)
}

func TestBlacklistHandlers_BulkDelete(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	_, _ = db.Exec("INSERT INTO ip_blacklist (ip) VALUES (?)", "6.6.6.6")
	_, _ = db.Exec("INSERT INTO ip_blacklist (ip) VALUES (?)", "7.7.7.7")

	var id1, id2 int64
	_ = db.QueryRow("SELECT id FROM ip_blacklist WHERE ip='6.6.6.6'").Scan(&id1)
	_ = db.QueryRow("SELECT id FROM ip_blacklist WHERE ip='7.7.7.7'").Scan(&id2)

	handler := bulkDeleteHandler(db, "ip_blacklist", cfg)
	
	req := models.BulkDeleteRequest{IDs: []int64{id1, id2}}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/api/ip-blacklist/bulk-delete", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	time.Sleep(100 * time.Millisecond)
}

func TestBlacklistHandlers_ClearAll(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	_, _ = db.Exec("INSERT INTO ip_blacklist (ip) VALUES (?)", "8.8.8.8")
	
	handler := clearAllHandler(db, "ip_blacklist", cfg, "ip")
	r := httptest.NewRequest("DELETE", "/api/ip-blacklist/clear-all", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 entries, got %d", count)
	}
	time.Sleep(100 * time.Millisecond)
}

func TestBlacklistHandlers_ImportContent(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewBlacklistHandlers(db, cfg)

	req := models.ImportBlacklistRequest{
		Type:    "ip",
		Content: "10.0.0.1\n# Comment\n10.0.0.2\n1.1.1.1",
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/api/blacklists/import", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.Import(w, r)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&count)
	if count < 3 {
		t.Errorf("Expected at least 3 entries imported, got %d", count)
	}
	time.Sleep(100 * time.Millisecond)
}
