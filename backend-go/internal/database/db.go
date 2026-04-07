// Package database provides SQLite initialization, schema management, and common helpers.
package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
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

	// Performance PRAGMAs — applied per-connection.
	for _, pragma := range []string{
		"PRAGMA cache_size = -50000",   // 50 MB page cache (vs default 2 MB)
		"PRAGMA mmap_size = 536870912", // 512 MB memory-mapped I/O
		"PRAGMA temp_store = MEMORY",   // temp tables in RAM, not /tmp
		"PRAGMA page_size = 4096",      // optimal for SSD
	} {
		if _, err := db.Exec(pragma); err != nil {
			log.Warn().Str("pragma", pragma).Err(err).Msg("pragma failed (non-fatal)")
		}
	}

	log.Info().Str("path", path).Msg("database opened")
	return db, nil
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
		`CREATE TABLE IF NOT EXISTS proxy_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT,
			source_ip TEXT,
			method TEXT,
			destination TEXT,
			status TEXT,
			bytes INTEGER,
			elapsed_ms INTEGER,
			unix_timestamp INTEGER
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
		"ALTER TABLE domain_whitelist ADD COLUMN type TEXT DEFAULT 'fqdn'",
	}
	for _, m := range migrations {
		_, _ = db.Exec(m) // "duplicate column" error is harmless
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
		{"aggressive_caching_enabled", "false"},
		{"offline_mode_enabled", "false"},
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
func ExportBlacklistsToFiles(db *sql.DB, configDir string) error {
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
	// 4. dnsmasq blocklist
	if err := writeDnsmasqBlocklist(db, configDir+"/dnsmasq.d/blocklist.conf", exclusions); err != nil {
		log.Warn().Err(err).Msg("dnsmasq blocklist write failed (non-fatal)")
	}
	return nil
}

// atomicWrite writes content to a temp file then renames to target path.
// Prevents torn reads by Squid/dnsmasq during concurrent writes.
func atomicWrite(path string, writeFn func(f *os.File) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	// #nosec G304
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := writeFn(f); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
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
		for _, l := range lines {
			fmt.Fprintln(f, l)
		}
		return nil
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
		for _, d := range domains {
			fmt.Fprintln(f, d)
		}
		return nil
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
				d := domain
				if strings.HasPrefix(d, "*.") {
					d = d[2:]
				}
				entries = append(entries, entry{d})
			}
		}
	}
	return atomicWrite(path, func(f *os.File) error {
		fmt.Fprintf(f, "# Generated by secure-proxy-manager at %s\n", time.Now().Format(time.RFC3339))
		for _, e := range entries {
			fmt.Fprintf(f, "address=/%s/0.0.0.0\naddress=/%s/::\n", e.domain, e.domain)
		}
		return nil
	})
}

// Audit writes a best-effort audit log row.
func Audit(db *sql.DB, username, action, target, details string) {
	db.Exec( //nolint:errcheck
		"INSERT INTO audit_log(username,action,target,details) VALUES(?,?,?,?)",
		username, action, target, details,
	)
}
