package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// The Audit page searches the whole log on the server: who, what, the target
// and the details, with the category, and the count is that of the matches.
// A % or _ typed is matched as itself.
func TestAuditLogSearchesTextOnTheServer(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	for _, r := range [][4]string{
		{"admin", "add_domain_blacklist", "ads.example.com", ""},
		{"admin", "login", "", "from 192.168.1.20"},
		{"ops", "update_settings", "enable_waf", "50% of the rules"},
		{"admin", "add_ip_whitelist", "203.0.113.7", "Allowed from the access log"},
		{"admin", "login_failed", "", "user ops_x"},
		// Unescaped, "50%" would match "5000" and "ops_" would match "opsy".
		{"admin", "import_ip_blacklist", "", "5000 entries"},
		{"admin", "logout", "", "opsy"},
	} {
		if _, err := db.Exec("INSERT INTO audit_log(username, action, target, details) VALUES(?, ?, NULLIF(?, ''), NULLIF(?, ''))", r[0], r[1], r[2], r[3]); err != nil {
			t.Fatal(err)
		}
	}
	h := NewAnalyticsHandlers(db, cfg)
	for _, c := range []struct {
		query string
		want  []string
	}{
		{"?q=example.com", []string{"add_domain_blacklist"}},
		{"?q=ops", []string{"logout", "login_failed", "update_settings"}},
		{"?q=ops&category=changes", []string{"update_settings"}},
		{"?q=192.168.1.20", []string{"login"}},
		{"?q=ACCESS+LOG", []string{"add_ip_whitelist"}},
		{"?q=50%25", []string{"update_settings"}},
		{"?q=ops_", []string{"login_failed"}},
		{"?q=nothing-matches", []string{}},
	} {
		code, rows, meta := auditPage(t, h, c.query)
		if code != http.StatusOK {
			t.Fatalf("%q = %d", c.query, code)
		}
		got := []string{}
		for _, r := range rows {
			got = append(got, r["action"].(string))
		}
		if len(got) != len(c.want) || (len(got) > 0 && func() bool {
			for i := range got {
				if got[i] != c.want[i] {
					return true
				}
			}
			return false
		}()) {
			t.Errorf("%q: actions %v, want %v", c.query, got, c.want)
		}
		if meta["total"] != float64(len(c.want)) {
			t.Errorf("%q: meta.total %v, want %d", c.query, meta["total"], len(c.want))
		}
	}
	if code, _, _ := auditPage(t, h, "?q="+strings.Repeat("a", 201)); code != http.StatusBadRequest {
		t.Errorf("a 201-character q = %d, want 400", code)
	}
	// The limit counts characters: 200 of them in two bytes each are allowed.
	if code, _, _ := auditPage(t, h, "?q="+url.QueryEscape(strings.Repeat("é", 200))); code != http.StatusOK {
		t.Errorf("a 200-character non-ASCII q = %d, want 200", code)
	}
}
