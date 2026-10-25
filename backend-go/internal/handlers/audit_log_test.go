package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func auditPage(t *testing.T, h *AnalyticsHandlers, query string) (int, []map[string]any, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	h.AuditLog(w, httptest.NewRequest("GET", "/api/audit-log"+query, nil))
	var body struct {
		Data []map[string]any `json:"data"`
		Meta map[string]any   `json:"meta"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body.Data, body.Meta
}

// The Audit page filters All / Changes / Sign-ins. Filtering one page of 50
// in the browser showed a near-empty page and a count of the whole log; the
// filter is applied by the backend, so the count and the pages are those of
// the filtered log.
func TestAuditLogFiltersByCategoryOnTheServer(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	for _, a := range []string{"login", "update_settings", "login_failed", "import_domain_blacklist", "logout", "clear_domain_blacklist"} {
		if _, err := db.Exec("INSERT INTO audit_log(username, action) VALUES('admin', ?)", a); err != nil {
			t.Fatal(err)
		}
	}
	h := NewAnalyticsHandlers(db, cfg)

	actions := func(rows []map[string]any) []string {
		out := []string{}
		for _, r := range rows {
			out = append(out, r["action"].(string))
		}
		return out
	}
	for _, c := range []struct {
		query string
		want  []string
	}{
		{"", []string{"clear_domain_blacklist", "logout", "import_domain_blacklist", "login_failed", "update_settings", "login"}},
		{"?category=all", []string{"clear_domain_blacklist", "logout", "import_domain_blacklist", "login_failed", "update_settings", "login"}},
		{"?category=signins", []string{"logout", "login_failed", "login"}},
		{"?category=changes", []string{"clear_domain_blacklist", "import_domain_blacklist", "update_settings"}},
	} {
		code, rows, meta := auditPage(t, h, c.query)
		if code != http.StatusOK {
			t.Fatalf("%q = %d", c.query, code)
		}
		if got := actions(rows); len(got) != len(c.want) || func() bool {
			for i := range got {
				if got[i] != c.want[i] {
					return true
				}
			}
			return false
		}() {
			t.Errorf("%q: actions %v, want %v", c.query, got, c.want)
		}
		if meta["total"] != float64(len(c.want)) {
			t.Errorf("%q: meta.total %v, want %d", c.query, meta["total"], len(c.want))
		}
		// The retention the page states comes from the worker that prunes.
		if meta["retention_days"] != float64(365) {
			t.Errorf("%q: meta.retention_days %v, want 365", c.query, meta["retention_days"])
		}
	}

	// A page of the filtered log, not a filter of a page.
	_, rows, meta := auditPage(t, h, "?category=changes&limit=2&offset=2")
	if len(rows) != 1 || rows[0]["action"] != "update_settings" || meta["total"] != float64(3) {
		t.Errorf("second page of changes = %v (total %v), want update_settings of 3", rows, meta["total"])
	}

	if code, _, _ := auditPage(t, h, "?category=everything"); code != http.StatusBadRequest {
		t.Errorf("unknown category = %d, want 400", code)
	}
}
