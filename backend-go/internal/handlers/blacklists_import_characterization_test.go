package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

// This file is a characterization suite: it fingerprints what Import actually
// does today, so the split of a 155-line, CCN-41 handler (SECURE-QUAL-02) can
// be shown to preserve behaviour rather than asserted to. Every expectation
// here was derived by running it against the pre-refactor handler. If a change
// forces an edit to this file, that change is not a refactor.

type importOutcome struct {
	Code    int
	Status  string
	Message string // set on success; errors carry Detail instead
	Detail  string
	Added   float64
	Skipped float64
	Bogon   float64
	Rows    map[string]string // entry -> description
}

func runImport(t *testing.T, h *BlacklistHandlers, db *sql.DB, payload string) importOutcome {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/blacklists/import", bytes.NewBufferString(payload))
	w := httptest.NewRecorder()
	h.Import(w, r)

	out := importOutcome{Code: w.Code, Rows: map[string]string{}}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, w.Body.String())
	}
	out.Status, _ = resp["status"].(string)
	out.Message, _ = resp["message"].(string)
	out.Detail, _ = resp["detail"].(string)
	if data, ok := resp["data"].(map[string]any); ok {
		out.Added, _ = data["added"].(float64)
		out.Skipped, _ = data["skipped"].(float64)
		out.Bogon, _ = data["bogon_skipped"].(float64)
	}
	for _, tbl := range [][2]string{{"ip_blacklist", "ip"}, {"domain_blacklist", "domain"}} {
		rows, err := db.Query("SELECT " + tbl[1] + ", description FROM " + tbl[0])
		if err != nil {
			t.Fatalf("reading %s: %v", tbl[0], err)
		}
		for rows.Next() {
			var entry, desc string
			if err := rows.Scan(&entry, &desc); err != nil {
				t.Fatalf("scan %s: %v", tbl[0], err)
			}
			out.Rows[entry] = desc
		}
		rows.Close()
	}
	return out
}

func (o importOutcome) entries() string {
	keys := make([]string, 0, len(o.Rows))
	for k := range o.Rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func TestImportBehaviour(t *testing.T) {
	t.Run("IP content: routable entries land, comments and junk are skipped", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		got := runImport(t, NewBlacklistHandlers(db, cfg), db, `{"type":"ip","content":"203.0.113.1\n# a comment\n; another comment\n\n203.0.113.2\nnot-an-ip\n198.51.100.0/24"}`)

		if got.Code != http.StatusOK || got.Status != "success" {
			t.Fatalf("got %d/%q", got.Code, got.Status)
		}
		if want := "198.51.100.0/24,203.0.113.1,203.0.113.2"; got.entries() != want {
			t.Errorf("entries = %q, want %q", got.entries(), want)
		}
		if got.Added != 3 || got.Skipped != 1 || got.Bogon != 0 {
			t.Errorf("added/skipped/bogon = %v/%v/%v, want 3/1/0", got.Added, got.Skipped, got.Bogon)
		}
		if want := "Imported on " + time.Now().Format("2006-01-02"); got.Rows["203.0.113.1"] != want {
			t.Errorf("description = %q, want %q", got.Rows["203.0.113.1"], want)
		}
	})

	t.Run("LAN bogons are refused and counted twice: once as skipped, once as bogon", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		got := runImport(t, NewBlacklistHandlers(db, cfg), db, `{"type":"ip","content":"192.168.5.5\n10.0.0.0/8\n127.0.0.1\n203.0.113.9"}`)

		if got.entries() != "203.0.113.9" {
			t.Errorf("entries = %q, want only the routable one", got.entries())
		}
		if got.Added != 1 || got.Skipped != 3 || got.Bogon != 3 {
			t.Errorf("added/skipped/bogon = %v/%v/%v, want 1/3/3", got.Added, got.Skipped, got.Bogon)
		}
		if !strings.Contains(got.Message, "private/bogon ranges were dropped") {
			t.Errorf("message must explain the bogon drop, got %q", got.Message)
		}
	})

	t.Run("no bogons means no bogon clause in the message", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		got := runImport(t, NewBlacklistHandlers(db, cfg), db, `{"type":"ip","content":"203.0.113.9"}`)
		if strings.Contains(got.Message, "bogon") {
			t.Errorf("message mentions bogons when none were dropped: %q", got.Message)
		}
		if want := "Successfully imported 1 entries (0 skipped/invalid)"; got.Message != want {
			t.Errorf("message = %q, want %q", got.Message, want)
		}
	})

	t.Run("domain content: hosts-file lines, schemes stripped, malformed skipped", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		got := runImport(t, NewBlacklistHandlers(db, cfg), db, `{"type":"domain","content":"0.0.0.0 evil.test\nhttps://tracker.test/path\nhttp://\nnodot\n.leading.test\ntrailing.test.\nplain.test"}`)

		if want := "evil.test,plain.test,tracker.test"; got.entries() != want {
			t.Errorf("entries = %q, want %q", got.entries(), want)
		}
		if got.Added != 3 || got.Skipped != 4 {
			t.Errorf("added/skipped = %v/%v, want 3/4", got.Added, got.Skipped)
		}
	})

	t.Run("entries already in the table are skipped, not re-added", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		if _, err := db.Exec("INSERT INTO ip_blacklist (ip, description) VALUES (?,?)", "203.0.113.1", "pre-existing"); err != nil {
			t.Fatal(err)
		}
		got := runImport(t, NewBlacklistHandlers(db, cfg), db, `{"type":"ip","content":"203.0.113.1\n203.0.113.2"}`)

		if got.Added != 1 || got.Skipped != 1 {
			t.Errorf("added/skipped = %v/%v, want 1/1", got.Added, got.Skipped)
		}
		if got.Rows["203.0.113.1"] != "pre-existing" {
			t.Errorf("an existing row must keep its description, got %q", got.Rows["203.0.113.1"])
		}
	})

	t.Run("a duplicate inside the payload is added once", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		got := runImport(t, NewBlacklistHandlers(db, cfg), db, `{"type":"ip","content":"203.0.113.1\n203.0.113.1\n203.0.113.1"}`)
		if got.Added != 1 || got.Skipped != 2 {
			t.Errorf("added/skipped = %v/%v, want 1/2", got.Added, got.Skipped)
		}
	})

	t.Run("an import larger than one batch lands in full", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		// batchSize is 5000; 5001 entries exercise the second, partial batch.
		var b strings.Builder
		for i := 0; i < 5001; i++ {
			b.WriteString("203.0." + itoa(i/256) + "." + itoa(i%256) + "\n")
		}
		got := runImport(t, NewBlacklistHandlers(db, cfg), db, `{"type":"ip","content":"`+strings.ReplaceAll(b.String(), "\n", `\n`)+`"}`)
		if got.Added != 5001 {
			t.Errorf("added = %v, want 5001", got.Added)
		}
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 5001 {
			t.Errorf("rows in table = %d, want 5001", n)
		}
	})

	t.Run("rejects a body that is neither url nor content", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		got := runImport(t, NewBlacklistHandlers(db, cfg), db, `{"type":"ip"}`)
		if got.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", got.Code)
		}
		if got.Detail != "either 'url' or 'content' must be provided" {
			t.Errorf("detail = %q", got.Detail)
		}
	})

	// The rejection happens in validate.Struct (`oneof=ip domain`) before the
	// handler's own check, so this pins the surface; TestImportTargetRefusesUnknownType
	// covers the check behind it, which no request can reach.
	t.Run("rejects an unknown list type", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		got := runImport(t, NewBlacklistHandlers(db, cfg), db, `{"type":"url","content":"203.0.113.1"}`)
		if got.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", got.Code)
		}
		if len(got.Rows) != 0 {
			t.Errorf("nothing may be written for an unknown type, got %v", got.Rows)
		}
	})

	t.Run("rejects malformed JSON", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		got := runImport(t, NewBlacklistHandlers(db, cfg), db, `{"type":`)
		if got.Code != http.StatusBadRequest || got.Detail != "invalid request body" {
			t.Errorf("got %d/%q", got.Code, got.Detail)
		}
	})

	t.Run("a loopback URL is refused as an SSRF target before any fetch", func(t *testing.T) {
		db, _, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Error("the server must never be reached")
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		got := runImport(t, NewBlacklistHandlers(db, cfg), db, `{"type":"ip","url":"`+ts.URL+`/list.txt"}`)
		if got.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", got.Code)
		}
		if !strings.Contains(got.Detail, "private/reserved networks are blocked") {
			t.Errorf("detail = %q", got.Detail)
		}
	})
}

// importTarget's default branch is defence in depth: the validator rejects any
// type but ip/domain first. Tested directly because a fallback to a default
// table would silently populate the IP blacklist with whatever was posted, and
// no request can exercise the branch to say so.
func TestImportTargetRefusesUnknownType(t *testing.T) {
	for _, blType := range []string{"url", "", "IP", "domains"} {
		if table, col, ok := importTarget(blType); ok {
			t.Errorf("importTarget(%q) = %q/%q/true, want no target", blType, table, col)
		}
	}
	if table, col, ok := importTarget("ip"); !ok || table != "ip_blacklist" || col != "ip" {
		t.Errorf("importTarget(\"ip\") = %q/%q/%v", table, col, ok)
	}
	if table, col, ok := importTarget("domain"); !ok || table != "domain_blacklist" || col != "domain" {
		t.Errorf("importTarget(\"domain\") = %q/%q/%v", table, col, ok)
	}
}
