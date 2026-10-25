package database

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A database at version 4 holds egress entries stored before "*." was
// refused. Squid reads "*.name" as a literal name that matches nothing, so
// version 5 rewrites each to ".name", removes the ones whose ".name" form is
// already listed, and writes one audit row naming the change.
func TestVersion5RewritesEgressWildcards(t *testing.T) {
	db := openInit(t)
	for _, s := range []string{
		"INSERT INTO dst_allowlist(entry, type) VALUES('*.a.example', 'domain')",
		"INSERT INTO dst_allowlist(entry, type) VALUES('*.b.example', 'domain')",
		"INSERT INTO dst_allowlist(entry, type) VALUES('.b.example', 'domain')",
		"INSERT INTO dst_allowlist(entry, type) VALUES('*.', 'domain')",
		"INSERT INTO dst_allowlist(entry, type) VALUES('c.example', 'domain')",
		"INSERT INTO dst_allowlist(entry, type) VALUES('x*.d.example', 'domain')",
		"INSERT INTO dst_allowlist(entry, type) VALUES('10.0.0.0/8', 'cidr')",
		"PRAGMA user_version = 4",
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	got := map[string]bool{}
	rows, err := db.Query("SELECT entry FROM dst_allowlist")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			t.Fatal(err)
		}
		got[e] = true
	}
	rows.Close()
	for _, want := range []string{".a.example", ".b.example", "c.example", "x*.d.example", "10.0.0.0/8"} {
		if !got[want] {
			t.Errorf("%q missing after the migration; have %v", want, got)
		}
	}
	for _, gone := range []string{"*.a.example", "*.b.example", "*."} {
		if got[gone] {
			t.Errorf("%q is still listed", gone)
		}
	}
	if len(got) != 5 {
		t.Errorf("%d entries, want 5: %v", len(got), got)
	}

	var user, target, details string
	if err := db.QueryRow("SELECT username, target, details FROM audit_log WHERE action = 'rewrite_egress_wildcards'").Scan(&user, &target, &details); err != nil {
		t.Fatalf("no audit row: %v", err)
	}
	var d struct {
		Rewritten int      `json:"rewritten"`
		Dropped   int      `json:"dropped"`
		Entries   []string `json:"entries"`
	}
	if err := json.Unmarshal([]byte(details), &d); err != nil {
		t.Fatalf("details %q: %v", details, err)
	}
	if user != "system" || target != "egress_allowlist" || d.Rewritten != 1 || d.Dropped != 2 ||
		len(d.Entries) != 1 || d.Entries[0] != "*.a.example > .a.example" {
		t.Errorf("audit row = %s %s %+v", user, target, d)
	}

	var v int
	_ = db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != schemaVersion {
		t.Errorf("user_version = %d, want %d", v, schemaVersion)
	}

	// The startup export writes what Squid reads: the rewritten form.
	dir := t.TempDir()
	if err := ExportBlacklistsToFiles(db, dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "dst_allow_domain.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), ".a.example\n") || strings.HasPrefix(string(b), "*.") || strings.Contains(string(b), "\n*.") {
		t.Errorf("dst_allow_domain.txt = %q", b)
	}

	// The step runs once: a second start writes no second audit row.
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'rewrite_egress_wildcards'").Scan(&n)
	if n != 1 {
		t.Errorf("%d audit rows after a second start, want 1", n)
	}
}

// A list with no "*." entry changes nothing and leaves no audit row.
func TestVersion5WithoutWildcardsWritesNoAuditRow(t *testing.T) {
	db := openInit(t)
	if _, err := db.Exec("INSERT INTO dst_allowlist(entry, type) VALUES('.e.example', 'domain'); PRAGMA user_version = 4"); err != nil {
		t.Fatal(err)
	}
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'rewrite_egress_wildcards'").Scan(&n)
	if n != 0 {
		t.Errorf("%d audit rows for a list without wildcards", n)
	}
}
