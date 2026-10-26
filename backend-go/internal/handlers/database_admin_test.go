package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestDatabaseHandlers_Reset_PreservesResetAuditRow(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewDatabaseHandlers(db)

	_, _ = db.Exec("INSERT INTO ip_blacklist (ip) VALUES ('198.51.100.10')")
	_, _ = db.Exec("INSERT INTO audit_log (username, action, target, details) VALUES ('admin', 'old_action', 'x', 'prior row')")

	r := withUserContext(httptest.NewRequest("POST", "/api/database/reset", nil), "admin")
	w := httptest.NewRecorder()
	h.Reset(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var auditCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&auditCount); err != nil {
		t.Fatalf("count audit_log: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("audit_log row count after reset = %d, want 1", auditCount)
	}

	var user, action, target, details string
	if err := db.QueryRow("SELECT username, action, target, details FROM audit_log").Scan(&user, &action, &target, &details); err != nil {
		t.Fatalf("scan audit_log: %v", err)
	}
	if user != "admin" || action != "database_reset" || target != "all" || details != "full database reset requested" {
		t.Errorf("audit_log row = (%q, %q, %q, %q), want (admin, database_reset, all, full database reset requested)",
			user, action, target, details)
	}
}

func TestDatabaseHandlers_Reset_RollsBackOnDeleteError(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewDatabaseHandlers(db)

	if _, err := db.Exec("INSERT INTO ip_blacklist (ip) VALUES ('198.51.100.11')"); err != nil {
		t.Fatalf("insert ip_blacklist: %v", err)
	}
	if _, err := db.Exec("INSERT INTO domain_blacklist (domain) VALUES ('example.org')"); err != nil {
		t.Fatalf("insert domain_blacklist: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO proxy_logs (timestamp, unix_timestamp, source_ip, destination, status)
		VALUES (datetime('now'), strftime('%s','now'), '10.0.0.5', 'example.org', 'TCP_DENIED/403')`); err != nil {
		t.Fatalf("insert proxy_logs: %v", err)
	}
	if _, err := db.Exec(`CREATE TRIGGER abort_proxy_logs_delete BEFORE DELETE ON proxy_logs
		BEGIN SELECT RAISE(ABORT, 'simulated delete failure'); END;`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	r := withUserContext(httptest.NewRequest("POST", "/api/database/reset", nil), "admin")
	w := httptest.NewRecorder()
	h.Reset(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when DELETE fails, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "proxy_logs") {
		t.Errorf("500 response body %q does not name the failing table proxy_logs", w.Body.String())
	}

	var ipCount, domCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&ipCount)
	_ = db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&domCount)
	if ipCount != 1 || domCount != 1 {
		t.Errorf("after failed reset: ip_blacklist=%d, domain_blacklist=%d; want 1, 1 (rolled back)", ipCount, domCount)
	}
}
