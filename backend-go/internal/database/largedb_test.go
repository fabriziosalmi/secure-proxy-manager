package database

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestGenerateLargeDB writes a database the size of the test deployment's:
// 1,000,000 proxy_logs rows, 640,000 domain_blacklist entries and 50,000
// ip_blacklist entries (about 0.5 GB with the indexes), at the current
// schema version, so a start-up against it does what a restart of that
// deployment does. It is a fixture generator, not a test: it runs only when
// SPM_LARGE_DB names the file to write, and the file is never committed.
//
//	SPM_LARGE_DB=/tmp/spm-large/proxy_manager.db go test ./internal/database -run TestGenerateLargeDB -v -timeout 30m
//
// SPM_LARGE_DB_LOGS, SPM_LARGE_DB_DOMAINS and SPM_LARGE_DB_IPS override the
// three row counts, for a quick smoke run on a small file first.
func TestGenerateLargeDB(t *testing.T) {
	path := os.Getenv("SPM_LARGE_DB")
	if path == "" {
		t.Skip("set SPM_LARGE_DB to the database file to generate")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("%s exists; the generator only writes a new file", path)
	}
	nLogs := envCount(t, "SPM_LARGE_DB_LOGS", 1_000_000)
	nDomains := envCount(t, "SPM_LARGE_DB_DOMAINS", 640_000)
	nIPs := envCount(t, "SPM_LARGE_DB_IPS", 50_000)

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Init(db, "admin", "$2a$10$abcdefghijklmnopqrstuuOd2a2qGa0NgB4xXyWJ2Qq5kM6lKX7W."); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	sourceID := insertListSource(t, db)
	seedDomainBlacklist(t, db, nDomains, sourceID)
	seedIPBlacklist(t, db, nIPs, sourceID)
	seedWhitelists(t, db)
	seedProxyLogs(t, db, nLogs)
	if _, err := db.Exec("ANALYZE"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s: %d logs, %d domains, %d ips, %.1f MiB, in %s",
		path, nLogs, nDomains, nIPs, float64(st.Size())/(1<<20), time.Since(start).Round(time.Second))
}

func envCount(t *testing.T, key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		t.Fatalf("%s=%q is not a count", key, v)
	}
	return n
}

// bulk runs fn inside one transaction with the statement prepared.
func bulk(t *testing.T, db *sql.DB, query string, fn func(stmt *sql.Stmt)) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(query)
	if err != nil {
		t.Fatal(err)
	}
	fn(stmt)
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func insertListSource(t *testing.T, db *sql.DB) int64 {
	res, err := db.Exec(`INSERT INTO list_sources(list, kind, source, label) VALUES('domain_blacklist','url',
		'https://example.invalid/hosts.txt','fixture feed')`)
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// fixtureDomain is a deterministic name shaped like a feed entry: a label, a
// second label and a TLD, 15 to 35 characters.
func fixtureDomain(i int) string {
	tlds := []string{"com", "net", "org", "io", "info", "xyz", "ru", "cn"}
	words := []string{"ads", "track", "metrics", "pixel", "cdn", "stat", "beacon", "telemetry", "adserver", "sync"}
	return fmt.Sprintf("%s-%x.%s%d.%s", words[i%len(words)], i*2654435761%0xffffff, words[(i/7)%len(words)], i%997, tlds[i%len(tlds)])
}

func seedDomainBlacklist(t *testing.T, db *sql.DB, n int, sourceID int64) {
	const batch = 50_000
	for from := 0; from < n; from += batch {
		bulk(t, db, "INSERT OR IGNORE INTO domain_blacklist(domain, description, source_id, added_date) VALUES(?, '', ?, ?)", func(stmt *sql.Stmt) {
			for i := from; i < from+batch && i < n; i++ {
				d := fixtureDomain(i)
				if i%50 == 0 {
					d = "*." + d // wildcard entries, as the feeds and the UI store them
				}
				added := time.Now().Add(-time.Duration(30+i%30) * 24 * time.Hour).UTC().Format("2006-01-02 15:04:05")
				if _, err := stmt.Exec(d, sourceID, added); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func seedIPBlacklist(t *testing.T, db *sql.DB, n int, sourceID int64) {
	bulk(t, db, "INSERT OR IGNORE INTO ip_blacklist(ip, description, source_id) VALUES(?, '', ?)", func(stmt *sql.Stmt) {
		for i := 0; i < n; i++ {
			ip := fmt.Sprintf("%d.%d.%d.%d", 1+i%223, (i/223)%256, (i/57088)%256, (i*7)%256)
			if i%10 == 0 {
				ip = fmt.Sprintf("%d.%d.%d.0/24", 1+i%223, (i/223)%256, (i/57088)%256)
			}
			if _, err := stmt.Exec(ip, sourceID); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func seedWhitelists(t *testing.T, db *sql.DB) {
	for i := 0; i < 20; i++ {
		if _, err := db.Exec("INSERT OR IGNORE INTO domain_whitelist(domain, type, description) VALUES(?, 'fqdn', 'fixture')", fixtureDomain(i*1000)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT OR IGNORE INTO ip_whitelist(ip, description) VALUES(?, 'fixture')", fmt.Sprintf("192.168.1.%d", 10+i)); err != nil {
			t.Fatal(err)
		}
	}
}

// seedProxyLogs writes n rows over the last 25 days (inside the default
// 30-day retention, so the start-up retention pass deletes nothing), with
// the mix the test deployment showed: mostly CONNECT, some plain HTTP and
// dnsmasq rows, about one in ten blocked under the reasons the tailer writes.
func seedProxyLogs(t *testing.T, db *sql.DB, n int) {
	const batch = 50_000
	now := time.Now().Unix()
	span := int64(25 * 24 * 3600)
	for from := 0; from < n; from += batch {
		bulk(t, db, `INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, elapsed_ms, blocked, event_id, block_reason)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, func(stmt *sql.Stmt) {
			for i := from; i < from+batch && i < n; i++ {
				ts := now - span + int64(i)*span/int64(n)
				src := fmt.Sprintf("192.168.1.%d", 10+i%60)
				method, dest := "CONNECT", fmt.Sprintf("host-%d.example.com:443", i%20000)
				switch i % 20 {
				case 1, 2, 3, 4:
					method, dest = "GET", fmt.Sprintf("http://www.site-%d.example.org/assets/img/%d.png?v=%d", i%8000, i%300, i%17)
				case 5:
					method, dest = "DNS", fmt.Sprintf("host-%d.example.com", i%20000)
				}
				blocked, reason, status := 0, "none", "TCP_TUNNEL/200"
				if method == "GET" {
					status = "TCP_MISS/200"
				}
				if method == "DNS" {
					status = "NOERROR"
				}
				var eventID any
				switch i % 100 {
				case 3, 13, 23, 33, 43:
					blocked, reason, status, dest = 1, "domain_blacklist_dns", "TCP_DENIED/403", fixtureDomain(i%640000)+":443"
				case 7, 17, 27:
					blocked, reason, status = 1, "unclassified", "TCP_DENIED/403"
				case 9:
					blocked, reason, status = 1, "direct_ip", "TCP_DENIED/403"
				case 59:
					blocked, reason, status = 1, "waf", "NONE_NONE/403"
					eventID = fmt.Sprintf("%08x-%04x-4%03x-a%03x-%012x", i, i%0xffff, i%0xfff, i%0xfff, i)
				case 61:
					status = "TCP_TUNNEL/503"
				}
				if _, err := stmt.Exec(time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05"), ts, src, method, dest,
					status, 500+i%90000, i%3000, blocked, eventID, reason); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
