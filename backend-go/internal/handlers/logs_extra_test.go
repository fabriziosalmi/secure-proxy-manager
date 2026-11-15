package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

// Deleting old logs deletes exactly the rows older than the days asked for,
// says how many, and is an audit event; a days that is not a whole number
// from 1 to 3650 is refused instead of falling back to 30 in silence.
func TestLogs_ClearOld(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewLogHandlers(db)
	now := time.Now()
	for _, age := range []time.Duration{40 * 24 * time.Hour, 31 * 24 * time.Hour, 29 * 24 * time.Hour, time.Hour} {
		insertLogRow(t, db, now.Add(-age), lanClient, "GET", "http://a.test/", 0, "none")
	}
	for _, bad := range []string{"0", "-1", "abc", "3651", "1.5"} {
		w := httptest.NewRecorder()
		h.ClearOld(w, httptest.NewRequest("POST", "/api/logs/clear-old?days="+bad, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("days=%s: %d, want 400", bad, w.Code)
		}
	}
	var left int
	_ = db.QueryRow("SELECT COUNT(*) FROM proxy_logs").Scan(&left)
	if left != 4 {
		t.Fatalf("a refused request deleted rows: %d left of 4", left)
	}
	w := httptest.NewRecorder()
	h.ClearOld(w, withUserContext(httptest.NewRequest("POST", "/api/logs/clear-old?days=30", nil), "admin"))
	var out struct {
		Data struct {
			Removed int `json:"removed"`
			Days    int `json:"days"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusOK || out.Data.Removed != 2 || out.Data.Days != 30 {
		t.Fatalf("days=30: %d %s, want 200 removing the 2 rows older than 30 days", w.Code, w.Body.String())
	}
	_ = db.QueryRow("SELECT COUNT(*) FROM proxy_logs").Scan(&left)
	if left != 2 {
		t.Errorf("%d rows left, want the 2 newer than 30 days", left)
	}
	wantDetails(t, oneAuditRow(t, db, "clear_old_logs"), map[string]any{"days": 30, "removed": 2})
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
