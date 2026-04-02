package database

import (
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

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
	Init(db, "admin", "hash")

	// Insert some test data
	db.Exec("INSERT INTO ip_blacklist (ip) VALUES (?)", "1.1.1.1")
	db.Exec("INSERT INTO domain_blacklist (domain) VALUES (?)", "evil.com")
	db.Exec("INSERT INTO domain_whitelist (domain, type) VALUES (?, ?)", "good.com", "fqdn")

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
	Init(db, "admin", "hash")

	Audit(db, "admin", "test_action", "test_target", "test_details")

	var count int
	db.QueryRow("SELECT count(*) FROM audit_log").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 audit entry, got %d", count)
	}
}
