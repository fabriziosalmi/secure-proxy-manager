package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// An entry two sources list, or one added by hand that a list already held,
// stays until no source is left. Removing the first source used to remove it:
// shared.example was gone while list B and the person who added it by hand
// still wanted it blocked, and a pasted list is never downloaded again.
func TestAnEntryStaysWhileASourceListsIt(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	pass := func(next http.Handler) http.Handler { return next }
	r := buildFullRouterOn(db, svc, cfg, pass)
	do := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req := withUserContext(httptest.NewRequest(method, path, strings.NewReader(body)), "admin")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	type source struct {
		ID      *int64 `json:"id"`
		Kind    string `json:"kind"`
		Entries int    `json:"entries"`
	}
	sources := func() []source {
		t.Helper()
		req := withUserContext(httptest.NewRequest("GET", "/api/domain-blacklist/sources", nil), "admin")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var out struct{ Data []source }
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		sort.Slice(out.Data, func(i, j int) bool { return *out.Data[i].ID < *out.Data[j].ID })
		return out.Data
	}
	listed := func() string {
		t.Helper()
		rows, err := db.Query("SELECT d.domain || '<-' || s.kind || s.id FROM domain_blacklist d JOIN list_sources s ON s.id = d.source_id ORDER BY d.domain")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var got []string
		for rows.Next() {
			var v string
			_ = rows.Scan(&v)
			got = append(got, v)
		}
		return strings.Join(got, ",")
	}
	remove := func(id int64) map[string]any {
		t.Helper()
		code, body := do("DELETE", "/api/domain-blacklist/sources/"+strconv.FormatInt(id, 10), "")
		if code != http.StatusOK {
			t.Fatalf("remove source %d: %d %v", id, code, body)
		}
		return body["data"].(map[string]any)
	}

	if code, body := do("POST", "/api/blacklists/import", `{"type":"domain","content":"shared.example\nonlya.example"}`); code != http.StatusOK {
		t.Fatalf("import A: %d %v", code, body)
	}
	code, body := do("POST", "/api/blacklists/import", `{"type":"domain","content":"shared.example\nonlyb.example"}`)
	if code != http.StatusOK || body["data"].(map[string]any)["also_listed"] != float64(1) {
		t.Fatalf("import B: %d %v; want shared.example recorded under B too (also_listed 1)", code, body)
	}
	code, body = do("POST", "/api/domain-blacklist", `{"domain":"shared.example"}`)
	if code != http.StatusOK || body["data"].(map[string]any)["recorded_by_hand"] != true {
		t.Fatalf("hand add of a listed domain: %d %v; want 200, recorded by hand", code, body)
	}
	s := sources()
	if len(s) != 3 || s[0].Entries != 2 || s[1].Entries != 2 || s[2].Kind != "manual" || s[2].Entries != 1 {
		t.Fatalf("sources = %+v; want A 2, B 2 (shared.example counts for both), manual 1", s)
	}
	a, b, manual := *s[0].ID, *s[1].ID, *s[2].ID

	if got := remove(a); got["removed"] != float64(1) || got["kept"] != float64(1) {
		t.Errorf("remove A = %v; want onlya removed, shared kept", got)
	}
	if got, want := listed(), "onlyb.example<-paste"+strconv.FormatInt(b, 10)+",shared.example<-paste"+strconv.FormatInt(b, 10); got != want {
		t.Errorf("after A: %s; want %s", got, want)
	}
	remove(b)
	if got, want := listed(), "shared.example<-manual"+strconv.FormatInt(manual, 10); got != want {
		t.Errorf("after B: %s; want %s (added by hand)", got, want)
	}
	if got := remove(manual); got["removed"] != float64(1) || got["kept"] != float64(0) {
		t.Errorf("remove the hand-added source = %v; want shared.example removed", got)
	}
	if got := listed(); got != "" {
		t.Errorf("no source left, still listed: %s", got)
	}
	var links int
	_ = db.QueryRow("SELECT COUNT(*) FROM domain_blacklist_sources").Scan(&links)
	if links != 0 {
		t.Errorf("%d rows of other sources left", links)
	}
}

// An entry deleted by itself takes the record of its other sources with it.
func TestDeletingAnEntryDeletesItsOtherSources(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	pass := func(next http.Handler) http.Handler { return next }
	r := buildFullRouterOn(db, svc, cfg, pass)
	call := func(method, path, body string) int {
		req := withUserContext(httptest.NewRequest(method, path, strings.NewReader(body)), "admin")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	call("POST", "/api/blacklists/import", `{"type":"ip","content":"203.0.113.7"}`)
	call("POST", "/api/ip-blacklist", `{"ip":"203.0.113.7"}`)
	var id, links int
	_ = db.QueryRow("SELECT id FROM ip_blacklist WHERE ip = '203.0.113.7'").Scan(&id)
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist_sources").Scan(&links)
	if links != 1 {
		t.Fatalf("hand add of a listed address: %d rows of other sources, want 1", links)
	}
	if code := call("POST", "/api/ip-blacklist/bulk-delete", `{"ids":[`+strconv.Itoa(id)+`]}`); code != http.StatusOK {
		t.Fatalf("bulk delete: %d", code)
	}
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist_sources").Scan(&links)
	if links != 0 {
		t.Errorf("%d rows of other sources outlived their entry", links)
	}
}
