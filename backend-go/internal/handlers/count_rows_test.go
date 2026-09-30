package handlers

import (
	"net/http/httptest"
	"testing"
)

// A failed COUNT used to be discarded, leaving total at 0 in the pagination
// envelope next to whatever page the list query returned. It must surface.
func TestCountRowsReturnsTheError(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()

	if _, err := db.Exec("INSERT INTO ip_blacklist(ip) VALUES('203.0.113.1'),('203.0.113.2')"); err != nil {
		t.Fatal(err)
	}
	if n, err := countRows(db, "SELECT COUNT(*) FROM ip_blacklist"); err != nil || n != 2 {
		t.Fatalf("countRows = %d, %v; want 2, nil", n, err)
	}
	if _, err := countRows(db, "SELECT COUNT(*) FROM no_such_table"); err == nil {
		t.Fatal("countRows swallowed a failing query")
	}
	db.Close()
	if _, err := countRows(db, "SELECT COUNT(*) FROM ip_blacklist"); err == nil {
		t.Fatal("countRows swallowed a closed database")
	}
}

func TestListEndpointsFailLoudlyWhenTheDatabaseIsGone(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	db.Close()

	for name, do := range map[string]func(w *httptest.ResponseRecorder){
		"blacklist": func(w *httptest.ResponseRecorder) {
			listHandler(db, "ip_blacklist", "ip").ServeHTTP(w, httptest.NewRequest("GET", "/api/ip-blacklist", nil))
		},
		"blacklist search": func(w *httptest.ResponseRecorder) {
			listHandler(db, "ip_blacklist", "ip").ServeHTTP(w, httptest.NewRequest("GET", "/api/ip-blacklist?search=x", nil))
		},
		"logs": func(w *httptest.ResponseRecorder) {
			NewLogHandlers(db).GetLogs(w, httptest.NewRequest("GET", "/api/logs", nil))
		},
		"audit": func(w *httptest.ResponseRecorder) {
			NewAnalyticsHandlers(db, cfg).AuditLog(w, httptest.NewRequest("GET", "/api/audit-log", nil))
		},
	} {
		w := httptest.NewRecorder()
		do(w)
		if w.Code != 500 {
			t.Errorf("%s: status %d, want 500", name, w.Code)
		}
	}
}
