package database

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// openAtVersion8 is a database as release 3.18.3 leaves it: every step up to
// version 8 run, list_sources with the version 4 CHECK (no 'preset').
func openAtVersion8(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "v8.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := createSchema(db); err != nil {
		t.Fatal(err)
	}
	for i, step := range []func(*sql.DB) error{
		migrateTypeConstraints, reconstructSinkholedBlocks, migrateListSources, rewriteEgressWildcards,
		deleteRetiredSettings, migrateEgressProviders, retireThreeSettings,
	} {
		if err := step(db); err != nil {
			t.Fatalf("step %d: %v", i+2, err)
		}
	}
	var v int
	_ = db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != 8 {
		t.Fatalf("seeded user_version = %d, want 8", v)
	}
	return db
}

type sourceRow struct {
	id                        int64
	list, kind, source, label string
}

func sourceRows(t *testing.T, db *sql.DB) []sourceRow {
	t.Helper()
	rows, err := db.Query("SELECT id, list, kind, source, label FROM list_sources ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []sourceRow
	for rows.Next() {
		var r sourceRow
		if err := rows.Scan(&r.id, &r.list, &r.kind, &r.source, &r.label); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// Version 9 rebuilds list_sources so 'preset' is a kind. On a database of the
// previous release it keeps every source with its id, every entry still points
// at its source, foreign keys stay enforced, and a preset source can then be
// recorded; before it, the CHECK refuses one.
func TestVersion9AcceptsPresetSourcesAndKeepsEverySource(t *testing.T) {
	db := openAtVersion8(t)

	if _, err := db.Exec("INSERT INTO list_sources(list, kind, source, label) VALUES('domain_whitelist','preset','docker','Common services: Docker')"); err == nil ||
		!strings.Contains(err.Error(), "CHECK") {
		t.Fatalf("version 8 accepted a preset source (err %v): the test database is not the old schema", err)
	}

	// Sources of every kind, with a gap in the ids (a removed source), and
	// entries pointing at them.
	urlID, err := KeyedSource(db, "domain_blacklist", SourceURL, "https://lists.example/hosts", "Example hosts")
	if err != nil {
		t.Fatal(err)
	}
	manualID, err := KeyedSource(db, "domain_whitelist", SourceManual, "", "")
	if err != nil {
		t.Fatal(err)
	}
	gone, _ := NewSource(db, "ip_blacklist", SourcePaste, "")
	if _, err := db.Exec("DELETE FROM list_sources WHERE id = ?", gone); err != nil {
		t.Fatal(err)
	}
	geoID, err := KeyedSource(db, "ip_blacklist", SourceGeo, "CN", "")
	if err != nil {
		t.Fatal(err)
	}
	restoreID, err := NewSource(db, "ip_whitelist", SourceRestore, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		q  string
		id int64
	}{
		{"INSERT INTO domain_blacklist(domain, source_id) VALUES('ads.example', ?)", urlID},
		{"INSERT INTO domain_whitelist(domain, source_id) VALUES('ok.example', ?)", manualID},
		{"INSERT INTO ip_blacklist(ip, source_id) VALUES('203.0.113.0/24', ?)", geoID},
		{"INSERT INTO ip_whitelist(ip, source_id) VALUES('198.51.100.7', ?)", restoreID},
	} {
		if _, err := db.Exec(s.q, s.id); err != nil {
			t.Fatalf("seed %q: %v", s.q, err)
		}
	}
	if _, err := db.Exec("INSERT INTO domain_blacklist(domain) VALUES('unrecorded.example')"); err != nil {
		t.Fatal(err)
	}
	before := sourceRows(t, db)

	if err := applyVersionedMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var v int
	_ = db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != 9 {
		t.Errorf("user_version = %d, want 9", v)
	}
	after := sourceRows(t, db)
	if len(after) != len(before) {
		t.Fatalf("%d sources after, %d before", len(after), len(before))
	}
	for i := range before {
		if after[i] != before[i] {
			t.Errorf("source %d changed: %+v, was %+v", i, after[i], before[i])
		}
	}
	for _, c := range []struct {
		q    string
		want int64
	}{
		{"SELECT source_id FROM domain_blacklist WHERE domain = 'ads.example'", urlID},
		{"SELECT source_id FROM domain_whitelist WHERE domain = 'ok.example'", manualID},
		{"SELECT source_id FROM ip_blacklist WHERE ip = '203.0.113.0/24'", geoID},
		{"SELECT source_id FROM ip_whitelist WHERE ip = '198.51.100.7'", restoreID},
	} {
		var got int64
		if err := db.QueryRow(c.q).Scan(&got); err != nil || got != c.want {
			t.Errorf("%s = %d (%v), want %d", c.q, got, err, c.want)
		}
	}
	var unrecorded int
	_ = db.QueryRow("SELECT COUNT(*) FROM domain_blacklist WHERE source_id IS NULL").Scan(&unrecorded)
	if unrecorded != 1 {
		t.Errorf("%d entries without a source, want the 1 seeded", unrecorded)
	}

	// Foreign keys are still enforced on the pool's connections: a removed
	// source with entries is refused, and so is an entry naming no source.
	for i := 0; i < 4; i++ {
		if _, err := db.Exec("DELETE FROM list_sources WHERE id = ?", urlID); err == nil {
			t.Fatal("a source with entries was deleted: foreign keys are off after the migration")
		}
	}
	if _, err := db.Exec("INSERT INTO domain_whitelist(domain, source_id) VALUES('dangling.example', 999999)"); err == nil {
		t.Error("an entry naming no source was accepted: foreign keys are off after the migration")
	}

	// A preset is a keyed source: one per list and preset.
	first, err := KeyedSource(db, "domain_whitelist", SourcePreset, "docker", "Common services: Docker")
	if err != nil {
		t.Fatalf("preset source: %v", err)
	}
	again, err := KeyedSource(db, "domain_whitelist", SourcePreset, "docker", "Common services: Docker")
	if err != nil || again != first {
		t.Errorf("second preset source = %d (%v), want the same %d", again, err, first)
	}
	if first <= restoreID {
		t.Errorf("new source id %d does not follow the highest kept id %d", first, restoreID)
	}

	// A second start changes nothing.
	if err := applyVersionedMigrations(db); err != nil {
		t.Fatal(err)
	}
	if n := len(sourceRows(t, db)); n != len(before)+1 {
		t.Errorf("%d sources after a second start, want %d", n, len(before)+1)
	}
}

// A new database reaches version 9 and takes preset sources.
func TestFreshDatabaseTakesPresetSources(t *testing.T) {
	db := openInit(t)
	if _, err := KeyedSource(db, "domain_blacklist", SourcePreset, "doh", "Common services: DNS-over-HTTPS resolvers"); err != nil {
		t.Fatal(err)
	}
}
