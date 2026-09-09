package database

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

// TestBlockedFlagMigration verifies the blocked-flag migration end to end: the
// backfill flips historical rows by the same token set the insert path uses, it
// is idempotent across re-runs of Init, and the partial index actually serves
// the recent-blocks lookup (proving the LIKE '%DENIED%' full scans are gone).
func TestBlockedFlagMigration(t *testing.T) {
	tmpDB := "/tmp/test_blocked_mig.db"
	defer os.Remove(tmpDB)

	db, err := Open(tmpDB)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Insert rows without setting blocked, so it takes the DEFAULT 0 (the legacy
	// ALTER path itself is covered by TestBlockedColumnAlterMigration). Three of
	// these are blocked statuses that the backfill must flip.
	statuses := []string{"TCP_DENIED/403", "TCP_MISS/200", "NONE/403", "TCP_TUNNEL/200", "X_BLOCKED/000"}
	for i, st := range statuses {
		if _, err := db.Exec(
			"INSERT INTO proxy_logs(timestamp, status, destination) VALUES(datetime('now'), ?, ?)",
			st, fmt.Sprintf("http://h%d.com", i),
		); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	var before int
	_ = db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE blocked = 1").Scan(&before)
	if before != 0 {
		t.Fatalf("expected 0 blocked before backfill, got %d", before)
	}

	// Re-running Init must backfill exactly the 3 blocked rows (idempotent).
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init #2: %v", err)
	}
	var after int
	_ = db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE blocked = 1").Scan(&after)
	if after != 3 {
		t.Errorf("expected 3 blocked after backfill, got %d", after)
	}
	// A second backfill pass must not change the count (idempotency).
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init #3: %v", err)
	}
	var stable int
	_ = db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE blocked = 1").Scan(&stable)
	if stable != 3 {
		t.Errorf("backfill not idempotent: got %d blocked, want 3", stable)
	}

	// The partial index must serve the recent-blocks lookup.
	rs, err := db.Query("EXPLAIN QUERY PLAN SELECT destination FROM proxy_logs WHERE blocked = 1 ORDER BY id DESC LIMIT 10")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rs.Close()
	used := false
	for rs.Next() {
		var id, parent, notused int
		var detail string
		if err := rs.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		if strings.Contains(detail, "idx_proxy_logs_blocked") {
			used = true
		}
	}
	if !used {
		t.Errorf("recent-blocks query does not use idx_proxy_logs_blocked partial index")
	}
}

// TestUnixTimestampIndexUsed proves the previously-dead idx_proxy_logs_unix_ts
// is now consulted: a time-bucketed range query (the TrafficStats/Timeline
// shape) range-scans the unix_timestamp index instead of doing TEXT-date math.
func TestUnixTimestampIndexUsed(t *testing.T) {
	tmpDB := "/tmp/test_unix_idx.db"
	defer os.Remove(tmpDB)

	db, err := Open(tmpDB)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	for i := 0; i < 1000; i++ {
		if _, err := db.Exec("INSERT INTO proxy_logs(timestamp, unix_timestamp, destination) VALUES(datetime('now'), ?, 'http://x')", 1700000000+i); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	rs, err := db.Query(`EXPLAIN QUERY PLAN
		SELECT strftime('%Y-%m-%d %H', datetime((unix_timestamp/300)*300,'unixepoch')) b, COUNT(*)
		FROM proxy_logs WHERE unix_timestamp >= 1700000500 GROUP BY b`)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rs.Close()
	used := false
	for rs.Next() {
		var id, parent, notused int
		var detail string
		if err := rs.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		if strings.Contains(detail, "idx_proxy_logs_unix_ts") {
			used = true
		}
	}
	if !used {
		t.Errorf("time-window query does not range-scan idx_proxy_logs_unix_ts (index still dead)")
	}
}

// TestBlockedColumnAlterMigration exercises the real upgrade path: a legacy
// proxy_logs table with NO blocked column, on which Init must run the
// idempotent ALTER ADD COLUMN (filling existing rows with 0) and then backfill.
func TestBlockedColumnAlterMigration(t *testing.T) {
	tmpDB := "/tmp/test_blocked_alter.db"
	defer os.Remove(tmpDB)

	db, err := Open(tmpDB)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	// Pre-create a legacy table with the full pre-blocked schema (everything the
	// indexes reference) but WITHOUT the blocked column, so Init's CREATE TABLE
	// IF NOT EXISTS is a no-op and the ALTER ADD COLUMN path runs.
	if _, err := db.Exec(`CREATE TABLE proxy_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT, source_ip TEXT, method TEXT, destination TEXT,
		status TEXT, bytes INTEGER, elapsed_ms INTEGER, unix_timestamp INTEGER)`); err != nil {
		t.Fatalf("legacy create: %v", err)
	}
	for _, st := range []string{"TCP_DENIED/403", "TCP_MISS/200", "NONE/403"} {
		if _, err := db.Exec("INSERT INTO proxy_logs(timestamp, status, destination) VALUES(datetime('now'), ?, 'http://x')", st); err != nil {
			t.Fatalf("legacy insert: %v", err)
		}
	}

	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init on legacy table: %v", err)
	}

	// The ALTER must have added the column (querying it must not error) and the
	// backfill must have flipped the two blocked rows.
	var blocked int
	if err := db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE blocked = 1").Scan(&blocked); err != nil {
		t.Fatalf("blocked column missing after Init (ALTER did not run): %v", err)
	}
	if blocked != 2 {
		t.Errorf("backfill on legacy table: got %d blocked, want 2", blocked)
	}
}

func TestOpenAndInit(t *testing.T) {
	tmpDB := "/tmp/test_proxy.db"
	defer os.Remove(tmpDB)

	db, err := Open(tmpDB)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	err = Init(db, "admin", "hash")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify tables exist
	var count int
	err = db.QueryRow("SELECT count(*) FROM users WHERE username='admin'").Scan(&count)
	if err != nil {
		t.Errorf("Failed to query users: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 admin user, got %d", count)
	}

	// Verify default settings
	var val string
	err = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='proxy_port'").Scan(&val)
	if err != nil {
		t.Errorf("Failed to query settings: %v", err)
	}
	if val != "3128" {
		t.Errorf("Expected proxy_port 3128, got %s", val)
	}
}

func TestExportBlacklistsToFiles(t *testing.T) {
	tmpDB := "/tmp/test_export.db"
	tmpConfig := "/tmp/test_config"
	defer os.Remove(tmpDB)
	defer os.RemoveAll(tmpConfig)

	db, _ := Open(tmpDB)
	defer db.Close()
	_ = Init(db, "admin", "hash")

	// Insert some test data
	_, _ = db.Exec("INSERT INTO ip_blacklist (ip) VALUES (?)", "1.1.1.1")
	_, _ = db.Exec("INSERT INTO domain_blacklist (domain) VALUES (?)", "evil.com")
	_, _ = db.Exec("INSERT INTO domain_whitelist (domain, type) VALUES (?, ?)", "good.com", "fqdn")

	err := ExportBlacklistsToFiles(db, tmpConfig)
	if err != nil {
		t.Errorf("Export failed: %v", err)
	}

	// Check if files exist
	if _, err := os.Stat(tmpConfig + "/ip_blacklist.txt"); os.IsNotExist(err) {
		t.Errorf("ip_blacklist.txt not created")
	}
	if _, err := os.Stat(tmpConfig + "/domain_blacklist.txt"); os.IsNotExist(err) {
		t.Errorf("domain_blacklist.txt not created")
	}
}

func TestAudit(t *testing.T) {
	tmpDB := "/tmp/test_audit.db"
	defer os.Remove(tmpDB)

	db, _ := Open(tmpDB)
	defer db.Close()
	_ = Init(db, "admin", "hash")

	Audit(db, "admin", "test_action", "test_target", "test_details")

	var count int
	_ = db.QueryRow("SELECT count(*) FROM audit_log").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 audit entry, got %d", count)
	}
}

// SECURE-DOM-05: migrations must now surface real errors while still tolerating
// the one expected failure. The regression risk of that change is idempotency —
// Init runs on every start and the ALTERs must keep being no-ops after the
// first run, not hard errors.
func TestInitIsIdempotentAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idem.db")
	for i := 1; i <= 3; i++ {
		db, err := Open(path)
		if err != nil {
			t.Fatalf("run %d: open: %v", i, err)
		}
		if err := Init(db, "admin", "$2a$10$abcdefghijklmnopqrstuv"); err != nil {
			t.Fatalf("run %d: Init returned an error on a database that is already migrated: %v", i, err)
		}
		db.Close()
	}
}

func TestIsDuplicateColumnErr(t *testing.T) {
	if isDuplicateColumnErr(nil) {
		t.Error("nil must not be treated as a duplicate-column error")
	}
	if !isDuplicateColumnErr(errors.New("SQL logic error: duplicate column name: blocked (1)")) {
		t.Error("SQLite's duplicate-column error was not recognised — Init would fail on every restart")
	}
	if isDuplicateColumnErr(errors.New("attempt to write a readonly database")) {
		t.Error("an unrelated error was swallowed as duplicate-column — that is the original bug")
	}
}

// SECURE-CONC-01: concurrent exports must not corrupt each other. With a fixed
// path+".tmp" the second writer's os.Create truncated the first one's file
// mid-write, and whichever renamed first published a short or NUL-padded ACL
// straight to Squid.
func TestExportBlacklistsToFilesIsConcurrencySafe(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "conc.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := Init(db, "admin", "$2a$10$abcdefghijklmnopqrstuv"); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Enough rows that each export takes long enough to overlap.
	for i := 0; i < 3000; i++ {
		if _, err := db.Exec("INSERT OR IGNORE INTO ip_blacklist(ip) VALUES(?)",
			fmt.Sprintf("203.0.113.%d/32", i%256)); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	var want int
	if err := db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&want); err != nil {
		t.Fatalf("count: %v", err)
	}

	cfgDir := filepath.Join(dir, "config")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ExportBlacklistsToFiles(db, cfgDir); err != nil {
				t.Errorf("export: %v", err)
			}
		}()
	}
	wg.Wait()

	// The published file must be a complete, uncorrupted export — not a
	// truncated or NUL-padded interleaving of two writers.
	data, err := os.ReadFile(filepath.Join(cfgDir, "ip_blacklist.txt"))
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	if bytes.ContainsRune(data, 0) {
		t.Error("exported blacklist contains NUL bytes — a concurrent writer truncated it")
	}
	got := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) != "" {
			got++
		}
	}
	if got != want {
		t.Errorf("exported %d entries, want %d — the file was published partially written", got, want)
	}

	// No temp files may survive a completed export.
	entries, _ := os.ReadDir(cfgDir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// SECURE-DOM-02. dst_allowlist.type routes an entry to one of two enforcement
// files, and both export queries are equality tests — so a row with any third
// value reaches neither, while the API and the UI keep listing it. New
// databases carry a CHECK; existing ones cannot, because SQLite needs a table
// rebuild to add one. The export must therefore refuse rather than silently
// drop the row.
func TestExportRefusesUnknownEgressType(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("init: %v", err)
	}

	// The CHECK protects a fresh database directly.
	if _, err := db.Exec("INSERT INTO dst_allowlist(entry,type) VALUES('x.test','regex')"); err == nil {
		t.Error("the CHECK constraint accepted a type outside {cidr,domain}")
	}

	// Simulate the pre-CHECK database an upgrade produces, where the constraint
	// could not be added, and assert the exporter refuses instead of writing
	// two files that both omit the row.
	if _, err := db.Exec("PRAGMA writable_schema=ON"); err != nil {
		t.Skipf("cannot simulate a pre-CHECK schema: %v", err)
	}
	if _, err := db.Exec(
		"UPDATE sqlite_master SET sql=replace(sql, \" CHECK (type IN ('cidr','domain'))\", '') WHERE name='dst_allowlist'",
	); err != nil {
		t.Skipf("cannot rewrite the schema: %v", err)
	}
	if _, err := db.Exec("PRAGMA writable_schema=OFF"); err != nil {
		t.Fatalf("writable_schema off: %v", err)
	}
	db.Close()
	db2, err := Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	if _, err := db2.Exec("INSERT INTO dst_allowlist(entry,type) VALUES('y.test','regex')"); err != nil {
		t.Skipf("pre-CHECK schema not reproduced: %v", err)
	}
	if err := ExportBlacklistsToFiles(db2, dir); err == nil {
		t.Error("the exporter wrote both allowlist files while a row belonged in neither")
	} else if !strings.Contains(err.Error(), "neither 'cidr' nor 'domain'") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}
