package database

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// reconstructFixture is a database at schema version 2 holding the rows the
// version 3 step decides on, as an upgraded install has them: logged before
// block reasons were recorded, so unclassified, and a sinkholed request with
// blocked = 0. Every name is listed on 2026-01-01 except late.example
// (2026-06-01); every row is logged on 2026-03-01.
func reconstructFixture(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "reconstruct.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	for _, s := range []string{
		`INSERT INTO domain_blacklist(domain, added_date) VALUES
			('dpm.demdex.net', '2026-01-01 00:00:00'),
			('*.static.chartbeat.com', '2026-01-01 00:00:00'),
			('Mixed.Example', '2026-01-01 00:00:00'),
			('late.example', '2026-06-01 00:00:00'),
			('allowed.example', '2026-01-01 00:00:00')`,
		`INSERT INTO domain_whitelist(domain, type) VALUES ('allowed.example', 'fqdn')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	const at = 1772323200 // 2026-03-01 00:00:00 UTC
	rows := []struct {
		dest, method, status, reason string
		ts                           any
	}{
		{"dpm.demdex.net:443", "CONNECT", "TCP_TUNNEL/503", "unclassified", at},                    // listed as "name"
		{"http://static.chartbeat.com/js/x.js", "GET", "TCP_MISS_ABORTED/503", "unclassified", at}, // listed as "*.name"
		{"MIXED.example:443", "CONNECT", "NONE_NONE/503", "unclassified", at},                      // case differs
		{"dpm.demdex.net:443", "CONNECT", "TCP_TUNNEL/503", "unclassified", nil},                   // no unix_timestamp yet
		{"unlisted.example:443", "CONNECT", "TCP_TUNNEL/503", "unclassified", at},
		{"late.example:443", "CONNECT", "TCP_TUNNEL/503", "unclassified", at}, // before it was listed
		{"allowed.example:443", "CONNECT", "TCP_TUNNEL/503", "unclassified", at},
		{"sub.dpm.demdex.net:443", "CONNECT", "TCP_TUNNEL/503", "unclassified", at},     // the hosts file is exact
		{"x.static.chartbeat.com:443", "CONNECT", "TCP_TUNNEL/503", "unclassified", at}, // "*.name" is the name only
		{"dpm.demdex.net:443", "CONNECT", "TCP_TUNNEL/200", "unclassified", at},         // not a 503
		{"dpm.demdex.net:443", "CONNECT", "TCP_TUNNEL/503", "none", at},                 // already classified
		{"dpm.demdex.net", "DNS", "TCP_TUNNEL/503", "unclassified", at},                 // a resolver row
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, blocked, block_reason)
			VALUES ('2026-03-01 00:00:00', ?, '192.168.1.109', ?, ?, ?, 0, ?)`, r.ts, r.method, r.dest, r.status, r.reason); err != nil {
			t.Fatal(err)
		}
	}
	// A row many id ranges further on: the update walks the whole table.
	if _, err := db.Exec(`INSERT INTO proxy_logs(id, timestamp, unix_timestamp, source_ip, method, destination, status, blocked, block_reason)
		VALUES (?, '2026-03-01 00:00:00', ?, '192.168.1.109', 'CONNECT', 'dpm.demdex.net:443', 'TCP_TUNNEL/503', 0, 'unclassified')`,
		farID, at); err != nil {
		t.Fatal(err)
	}
	// The release before this one: version 2.
	if _, err := db.Exec("PRAGMA user_version = 2"); err != nil {
		t.Fatal(err)
	}
	return db
}

// farID is the id of the fixture's last row, past several reconstructBatch ranges.
const farID = 5*reconstructBatch + 7

type logState struct {
	blocked int
	reason  string
}

func logStates(t *testing.T, db *sql.DB) map[int]logState {
	t.Helper()
	rows, err := db.Query("SELECT id, blocked, block_reason FROM proxy_logs ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int]logState{}
	for rows.Next() {
		var id int
		var s logState
		if err := rows.Scan(&id, &s.blocked, &s.reason); err != nil {
			t.Fatal(err)
		}
		out[id] = s
	}
	return out
}

func TestReconstructSinkholedBlocks(t *testing.T) {
	db := reconstructFixture(t)
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init on version 2: %v", err)
	}
	got := logStates(t, db)
	rec := logState{1, ReasonDNSReconstructed}
	kept := logState{0, "unclassified"}
	want := map[int]logState{
		1: rec, 2: rec, 3: rec, 4: rec,
		5: kept, 6: kept, 7: kept, 8: kept, 9: kept, 10: kept,
		11:    {0, "none"},
		12:    kept,
		farID: rec,
	}
	why := map[int]string{
		1: "a 503 to a name listed as name", 2: "a 503 to a name listed as *.name", 3: "a listed name in another case",
		4: "a row whose unix_timestamp is not filled yet", 5: "an unlisted name", 6: "a 503 logged before the name was listed",
		7: "a whitelisted name", 8: "a subdomain of a listed name", 9: "a subdomain of a *.name entry",
		10: "a status other than 503", 11: "an already classified row", 12: "a DNS resolver row",
		farID: "a row past the first id ranges",
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("row %d (%s) = %+v, want %+v", id, why[id], got[id], w)
		}
	}
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != schemaVersion {
		t.Errorf("user_version = %d (%v), want %d", v, err, schemaVersion)
	}
}

// The step runs once. A row with the same shape written after it ran (a Squid
// on an old logformat can still log an unclassified 503) is not reassigned by
// the next start, and the rows it reassigned stay as they are.
func TestReconstructSinkholedBlocksRunsOnce(t *testing.T) {
	db := reconstructFixture(t)
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	before := logStates(t, db)
	if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, blocked)
		VALUES (datetime('now'), strftime('%s','now'), '192.168.1.109', 'CONNECT', 'dpm.demdex.net:443', 'TCP_TUNNEL/503', 0)`); err != nil {
		t.Fatal(err)
	}
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	after := logStates(t, db)
	for id, s := range before {
		if after[id] != s {
			t.Errorf("row %d changed on the second start: %+v -> %+v", id, s, after[id])
		}
	}
	if late := after[farID+1]; late != (logState{0, "unclassified"}) {
		t.Errorf("a row written after the step ran was reassigned: %+v", late)
	}
}

// The rule itself is idempotent: run again over the same rows, it matches
// none, because a reassigned row is no longer unclassified.
func TestReconstructSinkholedBlocksIdempotent(t *testing.T) {
	db := reconstructFixture(t)
	if err := reconstructSinkholedBlocks(db); err != nil {
		t.Fatal(err)
	}
	first := logStates(t, db)
	if err := reconstructSinkholedBlocks(db); err != nil {
		t.Fatal(err)
	}
	second := logStates(t, db)
	n := 0
	for id, s := range first {
		if s.reason == ReasonDNSReconstructed {
			n++
		}
		if second[id] != s {
			t.Errorf("row %d changed on the second run: %+v -> %+v", id, s, second[id])
		}
	}
	if n != 5 {
		t.Errorf("first run reassigned %d rows, want 5", n)
	}
}
