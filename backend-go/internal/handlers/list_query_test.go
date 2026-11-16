package handlers

import (
	"net/http"
	"testing"
)

// GET on each list reads the limit, offset and search the document declares
// (listQuery): the summaries used to name page and page_size, which the
// handler never read.
func TestAListReadsTheQueryItDeclares(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	r := buildFullRouterOn(db, svc, cfg, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, withUserContext(req, "admin"))
		})
	})
	for _, l := range []struct{ path, a, b string }{
		{"/api/ip-blacklist", `{"ip":"203.0.113.1"}`, `{"ip":"198.51.100.2"}`},
		{"/api/ip-whitelist", `{"ip":"10.0.0.1"}`, `{"ip":"10.9.0.2"}`},
		{"/api/domain-blacklist", `{"domain":"one.example"}`, `{"domain":"two.example"}`},
		{"/api/domain-whitelist", `{"domain":"one.example"}`, `{"domain":"two.example"}`},
		{"/api/egress-allowlist", `{"entry":"one.example"}`, `{"entry":"two.example"}`},
	} {
		for _, body := range []string{l.a, l.b} {
			if code, out := call(t, r, "POST", l.path, body); code != http.StatusOK {
				t.Fatalf("seed %s: %d %v", l.path, code, out)
			}
		}
		count := func(q string) int {
			t.Helper()
			code, out := call(t, r, "GET", l.path+q, "")
			rows, ok := out["data"].([]any)
			if code != http.StatusOK || !ok {
				t.Fatalf("GET %s%s: %d %v", l.path, q, code, out)
			}
			return len(rows)
		}
		search := map[bool]string{true: "two", false: "198.51"}[l.path != "/api/ip-blacklist" && l.path != "/api/ip-whitelist"]
		if l.path == "/api/ip-whitelist" {
			search = "10.9"
		}
		if n := count(""); n != 2 {
			t.Errorf("%s: %d entries, want 2", l.path, n)
		}
		if n := count("?limit=1"); n != 1 {
			t.Errorf("%s?limit=1: %d entries, want 1", l.path, n)
		}
		if n := count("?offset=1"); n != 1 {
			t.Errorf("%s?offset=1: %d entries, want 1", l.path, n)
		}
		if n := count("?search=" + search); n != 1 {
			t.Errorf("%s?search=%s: %d entries, want 1", l.path, search, n)
		}
	}
}
