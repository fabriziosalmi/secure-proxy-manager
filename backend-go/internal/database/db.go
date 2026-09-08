// Package database provides SQLite initialization, schema management, and common helpers.
package database

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite" // register pure-Go SQLite driver
)

// Open opens (or creates) a SQLite database at path with WAL mode.
func Open(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("mkdir for db: %w", err)
	}
	// modernc.org/sqlite uses _pragma= syntax (not _journal_mode= like mattn/go-sqlite3).
	// Every PRAGMA goes in the DSN, where the driver applies it on each
	// connection it opens. cache_size, mmap_size and temp_store used to be
	// issued afterwards with db.Exec against a four-connection pool, which
	// configures whichever ONE connection serves that call — so the intended
	// 25x page-cache increase was absent from three connections out of four,
	// and from all of them once ConnMaxLifetime retired the configured one.
	// The comment above them claimed "applied per-connection"; it was not.
	// PRAGMA page_size was dropped: it cannot take effect after the database
	// has been created without a VACUUM (SECURE-PERF-02).
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)" +
		"&_pragma=synchronous(NORMAL)&_pragma=cache_size(-50000)&_pragma=mmap_size(268435456)" +
		"&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}
	// WAL mode allows concurrent readers + 1 writer.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(2 * time.Hour)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("db ping: %w", err)
	}

	// Verify WAL mode is active.
	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err == nil {
		log.Info().Str("journal_mode", journalMode).Msg("SQLite journal mode")
	}

	// Verify the per-connection settings actually took, rather than assuming.
	var cacheSize int
	if err := db.QueryRow("PRAGMA cache_size").Scan(&cacheSize); err == nil {
		log.Info().Int("cache_size", cacheSize).Msg("SQLite page cache")
	}

	log.Info().Str("path", path).Msg("database opened")
	return db, nil
}

// isDuplicateColumnErr reports whether err is SQLite's "duplicate column name"
// error, which ALTER TABLE ADD COLUMN returns when the migration already ran.
// That one is expected on every start after the first; nothing else is.
func isDuplicateColumnErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "duplicate column")
}

// Init runs an integrity check, creates tables, applies migrations, and seeds the admin user.
func Init(db *sql.DB, adminUsername, adminPasswordHash string) error {
	// Integrity check.
	var integrityResult string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrityResult); err != nil || integrityResult != "ok" {
		return fmt.Errorf("integrity check failed: %v (result=%s)", err, integrityResult)
	}

	var schema = []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			email TEXT,
			added_date TEXT DEFAULT (datetime('now')),
			last_login TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS ip_whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT UNIQUE NOT NULL,
			description TEXT,
			added_date TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS ip_blacklist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT UNIQUE NOT NULL,
			description TEXT,
			added_date TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS domain_blacklist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT UNIQUE NOT NULL,
			description TEXT,
			added_date TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS domain_whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT UNIQUE NOT NULL,
			type TEXT DEFAULT 'fqdn',
			description TEXT,
			added_date TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS dst_allowlist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			entry TEXT UNIQUE NOT NULL,
			type TEXT NOT NULL DEFAULT 'domain',
			description TEXT,
			added_date TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS proxy_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT,
			source_ip TEXT,
			method TEXT,
			destination TEXT,
			status TEXT,
			bytes INTEGER,
			elapsed_ms INTEGER,
			unix_timestamp INTEGER,
			blocked INTEGER NOT NULL DEFAULT 0,
			event_id TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_proxy_logs_timestamp ON proxy_logs(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_proxy_logs_source_ip ON proxy_logs(source_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_proxy_logs_ts_ip ON proxy_logs(timestamp, source_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_proxy_logs_ts_dest ON proxy_logs(timestamp, destination)`,
		`CREATE INDEX IF NOT EXISTS idx_proxy_logs_status ON proxy_logs(status)`,
		`CREATE INDEX IF NOT EXISTS idx_proxy_logs_unix_ts ON proxy_logs(unix_timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_proxy_logs_dest ON proxy_logs(destination)`,
		`CREATE TABLE IF NOT EXISTS settings (
			setting_name TEXT PRIMARY KEY,
			setting_value TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT,
			action TEXT,
			target TEXT,
			details TEXT,
			timestamp TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(timestamp)`,
	}

	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("schema exec: %w", err)
		}
	}

	// Column migrations (idempotent).
	migrations := []string{
		"ALTER TABLE proxy_logs ADD COLUMN source_ip TEXT",
		"ALTER TABLE proxy_logs ADD COLUMN unix_timestamp INTEGER",
		"ALTER TABLE proxy_logs ADD COLUMN method TEXT",
		"ALTER TABLE proxy_logs ADD COLUMN elapsed_ms INTEGER",
		"ALTER TABLE proxy_logs ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE proxy_logs ADD COLUMN event_id TEXT", // WAF correlation id (#107)
		"ALTER TABLE domain_whitelist ADD COLUMN type TEXT DEFAULT 'fqdn'",
	}
	for _, m := range migrations {
		// Only the expected "duplicate column" error is harmless — it means the
		// migration already ran. Discarding every error meant a locked,
		// read-only or full database produced a schema the process believed it
		// had, with the failure surfacing later as a missing column at query
		// time, or not at all (SECURE-DOM-05).
		if _, err := db.Exec(m); err != nil && !isDuplicateColumnErr(err) {
			return fmt.Errorf("migration %q: %w", m, err)
		}
	}

	// Indexes on migrated columns must be created AFTER the ALTERs above add the
	// columns — a legacy proxy_logs predates `blocked`, so this partial index
	// can't live in the schema slice (which runs before migrations) or its
	// `WHERE blocked = 1` would fail with "no such column" and abort Init on
	// upgrade. Only blocked rows are indexed, so it stays tiny.
	postMigrationIndexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_proxy_logs_blocked ON proxy_logs(blocked) WHERE blocked = 1`,
		// Correlation-id lookup (join a WAF event → its proxy_logs row). Partial:
		// only blocked rows carry an event_id, so the index stays tiny (#107).
		`CREATE INDEX IF NOT EXISTS idx_proxy_logs_event_id ON proxy_logs(event_id) WHERE event_id IS NOT NULL`,
	}
	for _, stmt := range postMigrationIndexes {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("post-migration index: %w", err)
		}
	}

	// Backfill unix_timestamp for rows written before it was populated, so the
	// idx_proxy_logs_unix_ts index covers historical data and time-window
	// analytics can range-scan on it instead of doing TEXT-date arithmetic.
	if _, err := db.Exec(
		`UPDATE proxy_logs SET unix_timestamp = CAST(strftime('%s', timestamp) AS INTEGER)
		 WHERE unix_timestamp IS NULL AND timestamp IS NOT NULL`,
	); err != nil {
		log.Warn().Err(err).Msg("backfill unix_timestamp failed (non-fatal)")
	}

	// Backfill the blocked flag for historical rows, using the exact same token
	// set the insert path derives it from, so old and new rows agree and the
	// idx_proxy_logs_blocked partial index covers all blocked rows. Idempotent:
	// only flips rows still at the default 0 that match.
	if _, err := db.Exec(
		`UPDATE proxy_logs SET blocked = 1
		 WHERE blocked = 0
		   AND (status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%')`,
	); err != nil {
		log.Warn().Err(err).Msg("backfill blocked flag failed (non-fatal)")
	}

	// Default settings.
	defaultSettings := [][]string{
		// Proxy configuration
		{"proxy_port", "3128"},
		{"cache_size", "1000"},
		{"memory_cache", "256"},
		{"allowed_networks", "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"},
		// Feature toggles
		{"ssl_bump_enabled", "false"},
		{"egress_default_deny", "false"},
		{"aggressive_caching_enabled", "false"},
		{"cache_bypass_domains", ""},
		{"enable_offline_mode", "false"},
		{"tailscale_enabled", "false"},
		{"ddns_enabled", "false"},
		// Security
		{"enable_ip_blacklist", "true"},
		{"enable_domain_blacklist", "true"},
		{"block_direct_ip", "false"},
		{"extra_ssl_ports", ""},
		{"enable_content_filtering", "false"},
		{"enable_waf", "false"},
		// Logging
		{"log_retention_days", "30"},
		// Notifications
		{"enable_notifications", "false"},
		{"webhook_url", ""},
		{"gotify_url", ""},
		{"gotify_token", ""},
		{"teams_webhook_url", ""},
		{"telegram_bot_token", ""},
		{"telegram_chat_id", ""},
		// Auto-refresh
		{"auto_refresh_enabled", "false"},
		{"auto_refresh_hours", "24"},
		// State
		{"default_password_changed", "false"},
	}
	for _, kv := range defaultSettings {
		db.Exec( //nolint:errcheck
			"INSERT OR IGNORE INTO settings(setting_name,setting_value) VALUES(?,?)",
			kv[0], kv[1],
		)
	}

	// Seed admin user.
	_, err := db.Exec(
		"INSERT OR IGNORE INTO users(username,password) VALUES(?,?)",
		adminUsername, adminPasswordHash,
	)
	if err != nil {
		return fmt.Errorf("seed admin: %w", err)
	}

	// Update query planner statistics for optimal index usage.
	if _, err := db.Exec("ANALYZE"); err != nil {
		log.Warn().Err(err).Msg("ANALYZE failed (non-fatal)")
	}

	log.Info().Msg("database initialised")
	return nil
}

// ExportBlacklistsToFiles writes the live blacklist tables to flat files used by Squid and dnsmasq.
// exportMu serialises ExportBlacklistsToFiles. Four contexts call it — the
// detached propagate goroutines, the blacklist-refresh worker and two
// maintenance handlers — and the six files it writes are consumed together, so
// they must be published as one consistent set rather than interleaved between
// two concurrent exports (SECURE-CONC-01).
var exportMu sync.Mutex

func ExportBlacklistsToFiles(db *sql.DB, configDir string) error {
	exportMu.Lock()
	defer exportMu.Unlock()
	// 1. ip_blacklist.txt
	if err := exportLines(db, configDir+"/ip_blacklist.txt",
		"SELECT ip FROM ip_blacklist ORDER BY ip"); err != nil {
		return err
	}
	// 2. ip_whitelist.txt
	if err := exportLines(db, configDir+"/ip_whitelist.txt",
		"SELECT ip FROM ip_whitelist ORDER BY ip"); err != nil {
		return err
	}
	// 3. domain_blacklist.txt (with whitelist exclusions)
	exclusions := loadWhitelistSet(db)
	if err := exportDomainBlacklist(db, configDir+"/domain_blacklist.txt", exclusions); err != nil {
		return err
	}
	// 3b. Egress destination allowlist (default-deny mode): split by type into a
	// CIDR/IP list and a domain list that Squid reads as `dst` / `dstdomain`.
	if err := exportLines(db, configDir+"/dst_allow_ip.txt",
		"SELECT entry FROM dst_allowlist WHERE type='cidr' ORDER BY entry"); err != nil {
		return err
	}
	if err := exportLines(db, configDir+"/dst_allow_domain.txt",
		"SELECT entry FROM dst_allowlist WHERE type='domain' ORDER BY entry"); err != nil {
		return err
	}
	// 4. dnsmasq blocklist (hosts format, re-read on SIGHUP). Remove the legacy
	// conf-dir address= file so it doesn't double-load with stale, restart-only data.
	_ = os.Remove(configDir + "/dnsmasq.d/blocklist.conf")
	if err := writeDnsmasqBlocklist(db, configDir+"/dnsmasq.d/blocklist.hosts", exclusions); err != nil {
		log.Warn().Err(err).Msg("dnsmasq blocklist write failed (non-fatal)")
	}
	return nil
}

// atomicWrite writes content to a temp file then renames to target path.
// Prevents torn reads by Squid/dnsmasq during concurrent writes.
func atomicWrite(path string, writeFn func(f *os.File) error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	// A UNIQUE temp file per writer, not path+".tmp". With a fixed name, a
	// second exporter's os.Create (O_TRUNC) reset the first one's file to zero
	// length while its handle was still open at its own offset, and whichever
	// renamed first published a short or NUL-padded ACL straight to Squid
	// (SECURE-CONC-01).
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // best-effort; a no-op once the rename succeeds

	if err := writeFn(f); err != nil {
		f.Close()
		return err
	}
	// fsync before the rename: Close flushes to the kernel but does not force
	// the data to disk, so on ext4 with delayed allocation a crash just after
	// the rename could leave a present, correctly named, ZERO-LENGTH file —
	// which Squid loads as an empty ACL and stops blocking (SECURE-DATA-05).
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Sync the directory too, so the rename itself is durable rather than only
	// the file contents.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func exportLines(db *sql.DB, path, query string) error {
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	var lines []string
	for rows.Next() {
		var line string
		if rows.Scan(&line) == nil && line != "" {
			lines = append(lines, line)
		}
	}
	return atomicWrite(path, func(f *os.File) error {
		w := bufio.NewWriter(f)
		for _, l := range lines {
			if _, err := fmt.Fprintln(w, l); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
		}
		return w.Flush()
	})
}

func loadWhitelistSet(db *sql.DB) map[string]struct{} {
	set := map[string]struct{}{}
	rows, err := db.Query("SELECT domain FROM domain_whitelist WHERE type='fqdn'")
	if err != nil {
		return set
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		if rows.Scan(&d) == nil {
			set[d] = struct{}{}
		}
	}
	return set
}

func exportDomainBlacklist(db *sql.DB, path string, exclusions map[string]struct{}) error {
	rows, err := db.Query("SELECT domain FROM domain_blacklist ORDER BY domain")
	if err != nil {
		return err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if rows.Scan(&domain) == nil && domain != "" {
			if _, excluded := exclusions[domain]; !excluded {
				domains = append(domains, domain)
			}
		}
	}
	return atomicWrite(path, func(f *os.File) error {
		w := bufio.NewWriter(f)
		for _, d := range domains {
			if _, err := fmt.Fprintln(w, d); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
		}
		return w.Flush()
	})
}

func writeDnsmasqBlocklist(db *sql.DB, path string, exclusions map[string]struct{}) error {
	rows, err := db.Query("SELECT domain FROM domain_blacklist ORDER BY domain")
	if err != nil {
		return err
	}
	defer rows.Close()

	type entry struct{ domain string }
	var entries []entry
	for rows.Next() {
		var domain string
		if rows.Scan(&domain) == nil && domain != "" {
			if _, excluded := exclusions[domain]; !excluded {
				d := strings.TrimPrefix(domain, "*.")
				entries = append(entries, entry{d})
			}
		}
	}
	// Emit a hosts-format file (consumed via dnsmasq addn-hosts) rather than
	// `address=` directives in a conf-dir file: dnsmasq RE-READS addn-hosts on
	// SIGHUP, so a blacklist change applies on reload instead of needing a full
	// DNS restart. No timestamp header — an unchanged blocklist produces a byte-
	// identical file, avoiding a pointless full re-parse on every export.
	// (Trade-off: hosts entries are exact-match, not the `/domain/` subdomain
	// wildcard; the imported lists are explicit domains, so this matches them.)
	return atomicWrite(path, func(f *os.File) error {
		w := bufio.NewWriter(f)
		for _, e := range entries {
			if _, err := fmt.Fprintf(w, "0.0.0.0 %s\n:: %s\n", e.domain, e.domain); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
		}
		return w.Flush()
	})
}

// Audit writes a best-effort audit log row.
func Audit(db *sql.DB, username, action, target, details string) {
	db.Exec( //nolint:errcheck
		"INSERT INTO audit_log(username,action,target,details) VALUES(?,?,?,?)",
		username, action, target, details,
	)
}
