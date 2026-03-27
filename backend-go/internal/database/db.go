// Package database provides SQLite initialization, schema management, and common helpers.
package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // register pure-Go SQLite driver
	"github.com/rs/zerolog/log"
)

// Open opens (or creates) a SQLite database at path with WAL mode.
func Open(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("mkdir for db: %w", err)
	}
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on&_synchronous=NORMAL"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}
	// Only 1 writer at a time (WAL handles readers separately).
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("db ping: %w", err)
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
			created_at TEXT DEFAULT (datetime('now')),
			last_login TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS ip_whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT UNIQUE NOT NULL,
			description TEXT,
			created_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS ip_blacklist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT UNIQUE NOT NULL,
			description TEXT,
			created_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS domain_blacklist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT UNIQUE NOT NULL,
			description TEXT,
			created_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS domain_whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT UNIQUE NOT NULL,
			type TEXT DEFAULT 'fqdn',
			description TEXT,
			created_at TEXT DEFAULT (datetime('now'))
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

func exportLines(db *sql.DB, path, query string) error {
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for rows.Next() {
		var line string
		if rows.Scan(&line) == nil && line != "" {
			fmt.Fprintln(f, line)
		}
	}
	return nil
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

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for rows.Next() {
		var domain string
		if rows.Scan(&domain) == nil && domain != "" {
			if _, excluded := exclusions[domain]; !excluded {
				fmt.Fprintln(f, domain)
			}
		}
	}
	return nil
}

func writeDnsmasqBlocklist(db *sql.DB, path string, exclusions map[string]struct{}) error {
	rows, err := db.Query("SELECT domain FROM domain_blacklist ORDER BY domain")
	if err != nil {
		return err
	}
	defer rows.Close()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# Generated by secure-proxy-manager at %s\n", time.Now().Format(time.RFC3339))
	for rows.Next() {
		var domain string
		if rows.Scan(&domain) == nil && domain != "" {
			if _, excluded := exclusions[domain]; !excluded {
				// Strip wildcard prefix if present.
				d := domain
				if strings.HasPrefix(d, "*.") {
					d = d[2:]
				}
				fmt.Fprintf(f, "address=/%s/\n", d)
			}
		}
	}
	return nil
}

// Audit writes a best-effort audit log row.
func Audit(db *sql.DB, username, action, target, details string) {
	db.Exec( //nolint:errcheck
		"INSERT INTO audit_log(username,action,target,details) VALUES(?,?,?,?)",
		username, action, target, details,
	)
}
