package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newFilledDB creates a database at the current schema with enough
// proxy_logs rows to span many pages, and closes it with the WAL folded in,
// so the file on disk is the whole database.
func newFilledDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy_manager.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3000; i++ {
		if _, err := tx.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, block_reason)
			VALUES(datetime('now'), strftime('%s','now'), ?, 'CONNECT', ?, 'TCP_TUNNEL/200', 'none')`,
			fmt.Sprintf("10.0.%d.%d", i/250, i%250), fmt.Sprintf("host-%d.example.com:443", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func rootPage(t *testing.T, path, name string) (page, pageSize int64) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRow("SELECT rootpage FROM sqlite_schema WHERE name = ?", name).Scan(&page); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		t.Fatal(err)
	}
	return page, pageSize
}

// damagePage overwrites the b-tree header of the page that roots name, which
// is what a torn write or a bad sector does to a database file.
func damagePage(t *testing.T, path, name string) {
	t.Helper()
	page, size := rootPage(t, path, name)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	junk := []byte(strings.Repeat("\xff", 64))
	if _, err := f.WriteAt(junk, (page-1)*size); err != nil {
		t.Fatal(err)
	}
}

// TestInitRefusesADamagedDatabase: a database whose pages are damaged still
// stops the start, as it did when Init ran the full check. quick_check reads
// every page, so it finds what the full check found here.
func TestInitRefusesADamagedDatabase(t *testing.T) {
	path := newFilledDB(t)
	damagePage(t, path, "proxy_logs")

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v (the damage is in a table page, which opening does not read)", err)
	}
	defer db.Close()
	err = Init(db, "admin", "hash")
	if err == nil {
		t.Fatal("Init accepted a database with a damaged page")
	}
	t.Logf("Init refused it: %v", err)
	if !strings.Contains(err.Error(), "integrity check failed") || !strings.Contains(err.Error(), "quick_check") {
		t.Errorf("Init failed, but not with the integrity check's error: %v", err)
	}

	if err := IntegrityCheck(context.Background(), path); err == nil {
		t.Error("the full integrity check passed a database with a damaged page")
	}
}

// misdeclareIndex makes idx_proxy_logs_source_ip declare a column its entries
// were not built from, through writable_schema: every page is sound, and the
// index no longer holds the rows of its table. Only the full integrity_check
// compares the two, which is the one case the start-up check gave up.
func misdeclareIndex(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		"PRAGMA writable_schema = ON",
		"UPDATE sqlite_schema SET sql = 'CREATE INDEX idx_proxy_logs_source_ip ON proxy_logs(destination)' WHERE name = 'idx_proxy_logs_source_ip'",
		"PRAGMA writable_schema = OFF",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// TestIntegrityCheckFindsWhatQuickCheckCannot: an index that does not match
// its table passes quick_check, so the start goes on, and fails the full
// check, whose failure is kept for readiness until a check passes.
func TestIntegrityCheckFindsWhatQuickCheckCannot(t *testing.T) {
	path := newFilledDB(t)
	misdeclareIndex(t, path)

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init refused a database whose pages are sound: %v", err)
	}

	err = IntegrityCheck(context.Background(), path)
	if err == nil {
		t.Fatal("the full integrity check passed an index that does not hold its table's rows")
	}
	if !strings.Contains(err.Error(), "idx_proxy_logs_source_ip") {
		t.Errorf("the failure does not name the damaged index: %v", err)
	}
	t.Logf("the full check reported: %v", err)

	t.Cleanup(func() { RecordIntegrity(nil) })
	RecordIntegrity(err)
	if got := IntegrityFailure(); got == "" || !strings.Contains(got, "integrity_check") {
		t.Errorf("IntegrityFailure() = %q after a failed check", got)
	}
	RecordIntegrity(nil)
	if got := IntegrityFailure(); got != "" {
		t.Errorf("IntegrityFailure() = %q after a passing check", got)
	}
}

// TestIntegrityCheckPassesASoundDatabase, while the pool holds the database
// open: the check reads its own snapshot on its own connection.
func TestIntegrityCheckPassesASoundDatabase(t *testing.T) {
	path := newFilledDB(t)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO audit_log(username, action) VALUES('admin', 'test')"); err != nil {
		t.Fatal(err)
	}
	if err := IntegrityCheck(context.Background(), path); err != nil {
		t.Fatalf("the full check failed a sound database: %v", err)
	}
}
