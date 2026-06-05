package database

import (
	"fmt"
	"os"
	"strings"
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
