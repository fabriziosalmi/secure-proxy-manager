package database

import "testing"

// A database at version 9 gets the four tables of other sources, empty (which
// other sources listed an entry was never stored), with every entry and its
// source unchanged; a second start changes nothing.
func TestVersion10AddsTheOtherSourcesOfAnEntry(t *testing.T) {
	db := openInit(t)
	url, manual := seedSources(t, db)
	for _, tb := range entrySourceTables {
		if _, err := db.Exec(string("DROP TABLE " + tb.sources)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("PRAGMA user_version = 9"); err != nil {
		t.Fatal(err)
	}
	for run := 1; run <= 2; run++ {
		if err := applyVersionedMigrations(db); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
	}
	var v, n, byURL, byManual int
	_ = db.QueryRow("PRAGMA user_version").Scan(&v)
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&n)
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist WHERE source_id = ?", url).Scan(&byURL)
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist WHERE source_id = ?", manual).Scan(&byManual)
	if v != schemaVersion || n != 5 || byURL != 2 || byManual != 1 {
		t.Errorf("version %d, %d entries (%d url, %d manual); want %d, 5 (2, 1)", v, n, byURL, byManual, schemaVersion)
	}
	for _, tb := range entrySourceTables {
		var rows int
		if err := db.QueryRow(string("SELECT COUNT(*) FROM " + tb.sources)).Scan(&rows); err != nil || rows != 0 {
			t.Errorf("%s: %d rows, %v; want an empty table", tb.sources, rows, err)
		}
	}
}

// The entries whose source was not recorded go when that group is removed,
// except those another source lists, which stay under it.
func TestRemovingUnrecordedEntriesKeepsThoseAnotherSourceLists(t *testing.T) {
	db := openInit(t)
	_, manual := seedSources(t, db)
	// 192.0.2.10 was there before sources were recorded; then added by hand.
	if ok, err := LinkListed(db, "ip_blacklist", "192.0.2.10", manual); err != nil || !ok {
		t.Fatalf("LinkListed = %v, %v", ok, err)
	}
	if ok, _ := LinkListed(db, "ip_blacklist", "192.0.2.10", manual); ok {
		t.Error("recording the same source twice reported a change")
	}
	if ok, _ := LinkListed(db, "ip_blacklist", "198.51.100.0/24", manual); ok {
		t.Error("a value's own source recorded as another of its sources")
	}
	removed, kept, err := RemoveSource(db, "ip_blacklist", 0)
	if err != nil || removed != 1 || kept != 1 {
		t.Fatalf("RemoveSource(unrecorded) = %d removed, %d kept, %v; want 1, 1", removed, kept, err)
	}
	var src, links int64
	_ = db.QueryRow("SELECT source_id FROM ip_blacklist WHERE ip = '192.0.2.10'").Scan(&src)
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist_sources").Scan(&links)
	if src != manual || links != 0 {
		t.Errorf("192.0.2.10 source %d (want %d), %d rows of other sources left (want 0)", src, manual, links)
	}
}
