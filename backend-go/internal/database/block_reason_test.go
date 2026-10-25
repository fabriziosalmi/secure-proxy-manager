package database

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestBlockReasonMigration is the upgrade path for block_reason: a table
// written by the previous release gets the column with every existing row
// unclassified (no reason is made up for them), and the blocked backfill that
// runs on every start no longer flips a row that has a reason. An origin
// server's own 403 is stored as reason none, blocked 0, and has to stay so.
func TestBlockReasonMigration(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "reason.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	// The previous release's proxy_logs: everything but block_reason.
	if _, err := db.Exec(`CREATE TABLE proxy_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT, source_ip TEXT, method TEXT, destination TEXT,
		status TEXT, bytes INTEGER, elapsed_ms INTEGER, unix_timestamp INTEGER,
		blocked INTEGER NOT NULL DEFAULT 0, event_id TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, method, status, blocked) VALUES
		(datetime('now'), 'GET', 'NONE_NONE/403', 1), (datetime('now'), 'CONNECT', 'TCP_TUNNEL/503', 0)`); err != nil {
		t.Fatal(err)
	}
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init on the previous schema: %v", err)
	}
	var legacy int
	if err := db.QueryRow(`SELECT COUNT(*) FROM proxy_logs WHERE block_reason = 'unclassified'`).Scan(&legacy); err != nil {
		t.Fatalf("block_reason missing after Init: %v", err)
	}
	if legacy != 2 {
		t.Errorf("existing rows unclassified: %d, want 2", legacy)
	}
	var tunnelBlocked int
	_ = db.QueryRow(`SELECT blocked FROM proxy_logs WHERE status = 'TCP_TUNNEL/503'`).Scan(&tunnelBlocked)
	if tunnelBlocked != 0 {
		t.Error("an existing row was reinterpreted as blocked")
	}

	if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, method, status, blocked, block_reason)
		VALUES(datetime('now'), 'GET', 'TCP_MISS/403', 0, 'none')`); err != nil {
		t.Fatal(err)
	}
	if err := Init(db, "admin", "hash"); err != nil { // the next start
		t.Fatalf("Init #2: %v", err)
	}
	var origin403 int
	_ = db.QueryRow(`SELECT blocked FROM proxy_logs WHERE block_reason = 'none'`).Scan(&origin403)
	if origin403 != 0 {
		t.Error("the start-up backfill flipped an origin 403 (reason none) to blocked")
	}

	// The DNS-row count behind the dashboard total is served by its index.
	rs, err := db.Query(`EXPLAIN QUERY PLAN SELECT COUNT(*) FROM proxy_logs WHERE method = 'DNS'`)
	if err != nil {
		t.Fatal(err)
	}
	var plan string
	for rs.Next() {
		var id, parent, notused int
		var detail string
		_ = rs.Scan(&id, &parent, &notused, &detail)
		plan += detail + "; "
	}
	rs.Close()
	if !strings.Contains(plan, "idx_proxy_logs_dns") {
		t.Errorf("the DNS-row count does not use idx_proxy_logs_dns: %s", plan)
	}
}
