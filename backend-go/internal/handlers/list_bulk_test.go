package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Every list removes several entries at once and empties itself the same
// way: the exceptions had neither, the blacklists and the default-deny
// allowlist had both. Each answers with the count it removed.
func TestEveryListRemovesSelectedEntriesAndEmptiesItself(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	for _, c := range []struct {
		path, table, col, field string
		values                  []string
	}{
		{"ip-blacklist", "ip_blacklist", "ip", "ip", []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}},
		{"domain-blacklist", "domain_blacklist", "domain", "domain", []string{"a.example", "b.example", "c.example"}},
		{"ip-whitelist", "ip_whitelist", "ip", "ip", []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}},
		{"domain-whitelist", "domain_whitelist", "domain", "domain", []string{"x.example", "y.example", "z.example"}},
		{"egress-allowlist", "dst_allowlist", "entry", "entry", []string{"p.example", "q.example", "r.example"}},
	} {
		for _, v := range c.values {
			if code, out := call(t, h, "POST", "/api/"+c.path, `{"`+c.field+`":"`+v+`"}`); code != http.StatusOK {
				t.Fatalf("add %s to %s = %d %v", v, c.path, code, out)
			}
		}
		ids := fmt.Sprintf("[%d,%d]", idOf(t, db, c.table, c.col, c.values[0]), idOf(t, db, c.table, c.col, c.values[1]))
		code, out := call(t, h, "POST", "/api/"+c.path+"/bulk-delete", `{"ids":`+ids+`}`)
		if code != http.StatusOK || out["data"].(map[string]any)["removed"] != float64(2) {
			t.Fatalf("%s bulk-delete = %d %v, want 200 and removed 2", c.path, code, out)
		}
		var left int
		_ = db.QueryRow("SELECT COUNT(*) FROM " + c.table).Scan(&left)
		if left != 1 {
			t.Errorf("%s: %d entries left after removing 2 of 3", c.path, left)
		}
		code, out = call(t, h, "DELETE", "/api/"+c.path+"/clear-all", "")
		if code != http.StatusOK || out["data"].(map[string]any)["removed"] != float64(1) {
			t.Fatalf("%s clear-all = %d %v, want 200 and removed 1", c.path, code, out)
		}
		wantDetails(t, oneAuditRow(t, db, "clear_"+auditListName(c.table)), map[string]any{"removed": 1})
	}
}

// A request for more than a thousand ids is refused before it reaches SQLite:
// 32,767 ids reached its limit on bound parameters and answered 500.
func TestBulkDeleteRefusesMoreThanAThousandIDs(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	ids := make([]string, 1001)
	for i := range ids {
		ids[i] = fmt.Sprint(i + 1)
	}
	if code, out := call(t, h, "POST", "/api/ip-blacklist/bulk-delete", `{"ids":[`+strings.Join(ids, ",")+`]}`); code != http.StatusBadRequest {
		t.Errorf("1001 ids = %d %v, want 400", code, out)
	}
	if code, _ := call(t, h, "POST", "/api/ip-blacklist/bulk-delete", `{"ids":[`+strings.Join(ids[:1000], ",")+`]}`); code != http.StatusOK {
		t.Errorf("1000 ids = %d, want 200", code)
	}
}
