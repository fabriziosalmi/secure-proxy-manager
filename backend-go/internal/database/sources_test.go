package database

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func openInit(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "spm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	return db
}

// A database at version 2 holds entries whose source was never recorded. The
// migration gives every list table a source_id, leaves those rows NULL (the
// page says "not recorded" instead of guessing), records version 3, and a
// second start changes nothing.
func TestVersion3GivesExistingEntriesAnUnrecordedSource(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := createSchema(db); err != nil {
		t.Fatal(err)
	}
	if err := migrateTypeConstraints(db); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"INSERT INTO ip_blacklist(ip, description) VALUES('203.0.113.1','Imported on 2026-10-25')",
		"INSERT INTO domain_blacklist(domain, description) VALUES('evil.test','Imported on 2026-10-25')",
		"INSERT INTO ip_whitelist(ip) VALUES('198.51.100.1')",
		"INSERT INTO domain_whitelist(domain) VALUES('ok.test')",
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	var v int
	_ = db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != 2 {
		t.Fatalf("seeded user_version = %d, want 2", v)
	}

	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	_ = db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != 3 {
		t.Errorf("user_version = %d, want 3", v)
	}
	for _, table := range listSourceTables {
		var n, unrecorded int
		if err := db.QueryRow("SELECT COUNT(*), SUM(source_id IS NULL) FROM "+table).Scan(&n, &unrecorded); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if n != 1 || unrecorded != 1 {
			t.Errorf("%s: %d rows, %d without a source; want the one seeded row, unrecorded", table, n, unrecorded)
		}
	}
	// Indexed, so the per-source counts do not walk the table.
	var idx int
	_ = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_domain_blacklist_source'").Scan(&idx)
	if idx != 1 {
		t.Error("idx_domain_blacklist_source is missing")
	}

	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init #2: %v", err)
	}
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&n)
	if n != 1 {
		t.Errorf("a second start changed domain_blacklist: %d rows", n)
	}
}

func TestFreshDatabaseRecordsSources(t *testing.T) {
	db := openInit(t)
	for _, table := range listSourceTables {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		has, err := hasColumn(tx, table, "source_id")
		_ = tx.Rollback()
		if err != nil || !has {
			t.Errorf("%s has no source_id (err %v)", table, err)
		}
	}
	// The column refers to a real source: a made-up id is refused.
	if _, err := db.Exec("INSERT INTO ip_blacklist(ip, source_id) VALUES('203.0.113.9', 999)"); err == nil {
		t.Error("an entry was stored with a source that does not exist")
	}
}

func TestKeyedSourceIsOneRowPerListAndKey(t *testing.T) {
	db := openInit(t)
	url := "https://lists.example/hosts.txt"
	a, err := KeyedSource(db, "domain_blacklist", SourceURL, url, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := KeyedSource(db, "domain_blacklist", SourceURL, url, "StevenBlack Unified")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("the same URL got two sources: %d and %d", a, b)
	}
	var label string
	_ = db.QueryRow("SELECT label FROM list_sources WHERE id = ?", a).Scan(&label)
	if label != "StevenBlack Unified" {
		t.Errorf("label = %q, want the Popular list name", label)
	}
	// An empty label does not erase the name.
	if _, err := KeyedSource(db, "domain_blacklist", SourceURL, url, ""); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow("SELECT label FROM list_sources WHERE id = ?", a).Scan(&label)
	if label != "StevenBlack Unified" {
		t.Errorf("label after a re-import without a name = %q", label)
	}
	other, _ := KeyedSource(db, "ip_blacklist", SourceURL, url, "")
	if other == a {
		t.Error("two lists share one source row")
	}
	p1, _ := NewSource(db, "domain_blacklist", SourcePaste, "")
	p2, _ := NewSource(db, "domain_blacklist", SourcePaste, "")
	if p1 == p2 {
		t.Error("two pasted lists share one source")
	}
	if _, err := KeyedSource(db, "dst_allowlist", SourceURL, url, ""); err != ErrUnknownList {
		t.Errorf("a list without provenance got a source: %v", err)
	}
	if _, err := KeyedSource(db, "ip_blacklist", SourcePaste, "", ""); err == nil {
		t.Error("a per-event kind was accepted as keyed")
	}
}

func seedSources(t *testing.T, db *sql.DB) (url, manual int64) {
	t.Helper()
	url, _ = KeyedSource(db, "ip_blacklist", SourceURL, "https://lists.example/ips.txt", "Firehol Level 1")
	manual, _ = KeyedSource(db, "ip_blacklist", SourceManual, "", "")
	for _, s := range []struct {
		ip, added string
		src       any
	}{
		{"203.0.113.1", "2026-10-25 08:00:00", url},
		{"203.0.113.2", "2026-10-25 08:02:00", url},
		{"198.51.100.0/24", "2026-10-25 09:00:00", manual},
		{"192.0.2.10", "2026-10-20 07:00:00", nil},
		{"192.0.2.11", "2026-10-21 07:00:00", nil},
	} {
		if _, err := db.Exec("INSERT INTO ip_blacklist(ip, added_date, source_id) VALUES(?,?,?)", s.ip, s.added, s.src); err != nil {
			t.Fatal(err)
		}
	}
	return url, manual
}

func TestListSourcesCountsTheEntriesOfEachSource(t *testing.T) {
	db := openInit(t)
	url, manual := seedSources(t, db)
	got, err := ListSources(db, "ip_blacklist")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d sources, want 3: %+v", len(got), got)
	}
	// Most recently added first, the unrecorded entries last.
	if got[0].ID == nil || *got[0].ID != manual || got[0].Kind != SourceManual || got[0].Entries != 1 {
		t.Errorf("first = %+v, want the manual source with 1 entry", got[0])
	}
	if got[1].ID == nil || *got[1].ID != url || got[1].Label != "Firehol Level 1" || got[1].Entries != 2 ||
		got[1].FirstAdded != "2026-10-25 08:00:00" || got[1].LastAdded != "2026-10-25 08:02:00" {
		t.Errorf("second = %+v, want the URL source with 2 entries from 08:00 to 08:02", got[1])
	}
	if got[2].ID != nil || got[2].Kind != SourceUnrecorded || got[2].Entries != 2 || got[2].FirstAdded != "2026-10-20 07:00:00" {
		t.Errorf("last = %+v, want the 2 unrecorded entries", got[2])
	}
	// A source left with no entries is not listed.
	if _, err := db.Exec("DELETE FROM ip_blacklist WHERE source_id = ?", manual); err != nil {
		t.Fatal(err)
	}
	got, _ = ListSources(db, "ip_blacklist")
	if len(got) != 2 {
		t.Errorf("after its entries went, the manual source is still listed: %+v", got)
	}
	if empty, _ := ListSources(db, "domain_whitelist"); empty == nil || len(empty) != 0 {
		t.Errorf("an empty list = %#v, want []", empty)
	}
}

func TestRemoveSourceRemovesExactlyItsEntries(t *testing.T) {
	db := openInit(t)
	url, manual := seedSources(t, db)
	n, err := RemoveSource(db, "ip_blacklist", url)
	if err != nil || n != 2 {
		t.Fatalf("RemoveSource = %d, %v; want 2 entries", n, err)
	}
	var left, sources int
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&left)
	_ = db.QueryRow("SELECT COUNT(*) FROM list_sources WHERE id = ?", url).Scan(&sources)
	if left != 3 || sources != 0 {
		t.Errorf("after removal: %d entries (want 3), source row present %d", left, sources)
	}

	n, err = RemoveSource(db, "ip_blacklist", 0)
	if err != nil || n != 2 {
		t.Fatalf("removing the unrecorded entries = %d, %v; want 2", n, err)
	}
	var onlyManual int
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist WHERE source_id = ?", manual).Scan(&onlyManual)
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&left)
	if left != 1 || onlyManual != 1 {
		t.Errorf("after removing the unrecorded entries: %d left, %d manual; want only the manual one", left, onlyManual)
	}
	if _, err := RemoveSource(db, "users", 1); err != ErrUnknownList {
		t.Errorf("RemoveSource on users = %v, want ErrUnknownList", err)
	}
}

func TestDropSourceIfEmptyKeepsASourceWithEntries(t *testing.T) {
	db := openInit(t)
	url, _ := seedSources(t, db)
	paste, _ := NewSource(db, "ip_blacklist", SourcePaste, "")
	DropSourceIfEmpty(db, "ip_blacklist", paste)
	DropSourceIfEmpty(db, "ip_blacklist", url)
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM list_sources WHERE id = ?", paste).Scan(&n)
	if n != 0 {
		t.Error("an empty pasted-list source was kept")
	}
	_ = db.QueryRow("SELECT COUNT(*) FROM list_sources WHERE id = ?", url).Scan(&n)
	if n != 1 {
		t.Error("a source with entries was dropped")
	}
}
