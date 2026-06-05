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

	// Simulate rows written before the blocked column existed: don't set it, so
	// it takes the DEFAULT 0. Three of these are blocked statuses.
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
