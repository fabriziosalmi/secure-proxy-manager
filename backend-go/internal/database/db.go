// Package database provides SQLite initialization, schema management, and common helpers.
package database

import (
	"bufio"
	"context"
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

// PageCacheKiB is the page cache each pooled connection may fill, in KiB
// (PRAGMA cache_size, negative). It is per connection, the pool holds four,
// and every one of them lives in the backend's 128 MiB.
//
// It was 50,000 (50 MB). The cache is allocated outside the Go heap, and a
// 4 KiB page with its header takes an 8 KiB allocation, so a full cache cost
// about 110 MiB of anonymous memory: measured on 1,000,000 proxy_logs rows,
// one start-up integrity check or one 7-day destination report filled it.
// Two connections doing so needed twice the container. The same report took
// the same time with an 8 MB cache (3.3 to 5.0 s warm at 0.25 CPU against 4.4
// to 4.8 s): the working set of such a scan is larger than either cache, and
// the kernel's file cache, which the limit can reclaim, serves the rest. At
// 8 MB a full cache measured 19 to 21 MiB, four of them about 80 MiB.
const PageCacheKiB = 8000

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
		fmt.Sprintf("&_pragma=synchronous(NORMAL)&_pragma=cache_size(-%d)&_pragma=mmap_size(268435456)", PageCacheKiB) +
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

var schemaStatements = []string{
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
		type TEXT NOT NULL DEFAULT 'fqdn' CHECK (type IN ('fqdn')),
		description TEXT,
		added_date TEXT DEFAULT (datetime('now'))
	)`,
	// CHECK on type: the column decides which enforcement file an entry
	// reaches, and both export queries are equality tests — so a row with
	// any third value is listed in the UI and written to NEITHER file
	// (SECURE-DOM-02). New databases get the constraint here; existing ones
	// get it from the versioned migration in migrate.go, because SQLite
	// needs a table rebuild to add one and CREATE TABLE IF NOT EXISTS is a
	// no-op for them. The exporter below still refuses to run silently past
	// an unrecognised type, as a second line of defence.
	`CREATE TABLE IF NOT EXISTS dst_allowlist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		entry TEXT UNIQUE NOT NULL,
		type TEXT NOT NULL DEFAULT 'domain' CHECK (type IN ('cidr','domain')),
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
		event_id TEXT,
		block_reason TEXT NOT NULL DEFAULT 'unclassified',
		resolved_ip TEXT
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
	// What the WAF said about each block (waf_events.go), keyed by the event
	// ID the access log row carries. A new table, so no versioned step: this
	// statement creates it on an existing database too.
	`CREATE TABLE IF NOT EXISTS waf_events (
		event_id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL DEFAULT (datetime('now')),
		client_ip TEXT NOT NULL DEFAULT '',
		host TEXT NOT NULL DEFAULT '',
		path TEXT NOT NULL DEFAULT '',
		url TEXT NOT NULL DEFAULT '',
		source TEXT NOT NULL DEFAULT '',
		blocked_by TEXT NOT NULL DEFAULT '',
		score INTEGER NOT NULL DEFAULT 0,
		crs_score INTEGER NOT NULL DEFAULT 0,
		rules TEXT NOT NULL DEFAULT '[]',
		categories TEXT NOT NULL DEFAULT '[]',
		crs_targets TEXT NOT NULL DEFAULT '[]'
	)`,
	`CREATE INDEX IF NOT EXISTS idx_waf_events_ts ON waf_events(timestamp)`,
}

// createSchema creates every table and index the schema declares. It is
// idempotent: each statement is CREATE ... IF NOT EXISTS.
func createSchema(db *sql.DB) error {
	for _, stmt := range schemaStatements {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("schema exec: %w", err)
		}
	}

	return nil
}

// applyColumnMigrations is version 1 of the schema plus the versioned steps that
// follow it: see the comments below.
func applyColumnMigrations(db *sql.DB) error {
	// Version 1 of the schema: column additions, replayed on every start and
	// harmless once applied. Anything that cannot be replayed goes in
	// applyVersionedMigrations (migrate.go), which records its progress in
	// PRAGMA user_version.
	migrations := []string{
		"ALTER TABLE proxy_logs ADD COLUMN source_ip TEXT",
		"ALTER TABLE proxy_logs ADD COLUMN unix_timestamp INTEGER",
		"ALTER TABLE proxy_logs ADD COLUMN method TEXT",
		"ALTER TABLE proxy_logs ADD COLUMN elapsed_ms INTEGER",
		"ALTER TABLE proxy_logs ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE proxy_logs ADD COLUMN event_id TEXT", // WAF correlation id (#107)
		// The rule that blocked the request, or 'none' (workers/block_reason.go).
		// Rows that predate it read 'unclassified': their blocked flag came from
		// the status heuristic and no reason was recorded, so none is invented,
		// except the one declared case schema version 3 reassigns (reconstruct.go).
		// ADD COLUMN with a constant default rewrites no row.
		"ALTER TABLE proxy_logs ADD COLUMN block_reason TEXT NOT NULL DEFAULT 'unclassified'",
		"ALTER TABLE domain_whitelist ADD COLUMN type TEXT DEFAULT 'fqdn'",
		// The upstream address Squid connected to (workers.extractResolvedIP);
		// NULL for older rows and for requests that reached no server.
		"ALTER TABLE proxy_logs ADD COLUMN resolved_ip TEXT",
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

	if err := applyVersionedMigrations(db); err != nil {
		return err
	}

	return nil
}

// createPostMigrationIndexes creates the indexes that depend on migrated columns.
func createPostMigrationIndexes(db *sql.DB) error {
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
		// The dnsmasq rows (method DNS) are left out of every client statistic.
		// The lifetime total is COUNT(*) minus their count, and this partial
		// index keeps that count from walking the table.
		`CREATE INDEX IF NOT EXISTS idx_proxy_logs_dns ON proxy_logs(unix_timestamp) WHERE method = 'DNS'`,
		// The access log's rule filter (GET /api/logs?reason=). Blocked rows
		// only, like idx_proxy_logs_blocked, and in id order within a rule, so
		// the newest page of one rule is read straight from it and its count
		// never touches the table. Measured on 1M rows: docs/api/logs.md.
		`CREATE INDEX IF NOT EXISTS idx_proxy_logs_blocked_reason ON proxy_logs(block_reason) WHERE blocked = 1`,
		// The domain blacklist entries with an upper-case letter, which the
		// UNIQUE index cannot find from a lower-case allowed name: the count
		// of entries the allowed list takes out (BlockedOnAllowed) reads them
		// from here instead of every entry. Imports keep the feed's case, so
		// it is usually empty.
		`CREATE INDEX IF NOT EXISTS idx_domain_blacklist_mixed_case ON domain_blacklist(domain) WHERE domain != lower(domain)`,
	}
	for _, stmt := range postMigrationIndexes {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("post-migration index: %w", err)
		}
	}
	return nil
}

// backfillProxyLogs fills columns added after rows already existed. Failures
// are logged, not fatal: the rows are still readable without the backfill.
func backfillProxyLogs(db *sql.DB) {
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
	// only flips rows still at the default 0 that match. Only unclassified rows:
	// a row with a reason has its flag from that reason, and an origin
	// server's own 403 (reason none) is not a block.
	if _, err := db.Exec(
		`UPDATE proxy_logs SET blocked = 1
		 WHERE blocked = 0 AND block_reason = 'unclassified'
		   AND (status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%')`,
	); err != nil {
		log.Warn().Err(err).Msg("backfill blocked flag failed (non-fatal)")
	}
}

// DefaultBlockedFileTypes is the extension list a new install stores, the
// same as the UI's Family profile. Not com: the pattern matches the end of
// any URL path, and paths such as /whois/example.com end in .com.
const DefaultBlockedFileTypes = "exe,bat,cmd,dll,msi,scr,ps1,vbs"

// DefaultCacheSizeMB is the disk cache size (in MB) a new install stores,
// matching PROXY_CACHE_SIZE_MB in proxy/generate_squid_conf.sh.
const DefaultCacheSizeMB = "2000"

// DefaultSettings is every setting a new database starts with, as name and
// value. The handlers derive the boolean settings from it (the ones whose
// default is "true" or "false") so each one gets a value check.
var DefaultSettings = [][]string{
	// Proxy configuration
	{"proxy_port", "3128"},
	{"cache_size", DefaultCacheSizeMB},
	{"memory_cache", "256"},
	// Feature toggles
	{"ssl_bump_enabled", "false"},
	{"egress_default_deny", "false"},
	{"aggressive_caching_enabled", "false"},
	{"cache_bypass_domains", ""},
	{"enable_offline_mode", "false"},
	{"extra_ssl_ports", ""},
	{"enable_safesearch", "false"},
	{"enable_youtube_restricted", "false"},
	{"enable_proxy_auth", "false"},
	// Content filtering is off, but its list is stored, so turning the
	// switch on blocks something. Without a stored list the page showed
	// "exe,bat,cmd,dll,js" as a fallback that was never saved, no file
	// was written, and the generator left the rule out: on with nothing
	// blocked. The list is the Windows formats that run on a double click
	// and are how droppers arrive. No archives or documents (normal
	// downloads), no js or css (every web page loads them; the pattern
	// matches any URL path ending so).
	{"enable_content_filtering", "false"},
	{"blocked_file_types", DefaultBlockedFileTypes},
	// The values the backend writes when the switch is on and nothing is
	// stored (writeBandwidthSettings, writeTimeRestrictions), stored so the
	// page shows what will be applied instead of a value of its own.
	{"enable_bandwidth_limits", "false"},
	{"bandwidth_limit_mbps", "100"},
	{"bandwidth_limit_per_user_kbps", "0"},
	{"enable_time_restrictions", "false"},
	{"time_restriction_start", "08:00"},
	{"time_restriction_end", "18:00"},
	// The WAF heuristics as the shipped compose starts the WAF
	// (WAF_H_*: all on except sequence validation). With no row the page
	// showed every heuristic on, sequence validation included, while the
	// WAF ran it off.
	{"waf_h_entropy", "true"},
	{"waf_h_beaconing", "true"},
	{"waf_h_pii", "true"},
	{"waf_h_sharding", "true"},
	{"waf_h_ghosting", "true"},
	{"waf_h_sequence", "false"},
	// Logging
	{"log_retention_days", "30"},
	{"gdpr_mode", "false"},
	// Notifications
	{"enable_notifications", "false"},
	{"webhook_url", ""},
	{"gotify_url", ""},
	{"gotify_token", ""},
	{"teams_webhook_url", ""},
	{"telegram_bot_token", ""},
	{"telegram_chat_id", ""},
	// Notification limits (handlers/notify_limit.go, which reads a missing
	// or unusable value as these same defaults): group alerts from one
	// address for 10 minutes, at most 20 deliveries per channel per hour,
	// both event types on, every level.
	{"notify_group_window_minutes", "10"},
	{"notify_max_per_hour", "20"},
	{"notify_waf_block", "true"},
	{"notify_login_failure", "true"},
	{"notify_min_level", "info"},
	// Auto-refresh
	{"auto_refresh_enabled", "false"},
	{"auto_refresh_hours", "24"},
	{"egress_provider_refresh_hours", "24"},
	// State
	{"default_password_changed", "false"},
}

// seedDefaultSettings inserts any default setting that is not already present.
func seedDefaultSettings(db *sql.DB) {
	for _, kv := range DefaultSettings {
		db.Exec( //nolint:errcheck
			"INSERT OR IGNORE INTO settings(setting_name,setting_value) VALUES(?,?)",
			kv[0], kv[1],
		)
	}
}

// seedAdmin creates the admin user if there is none.
func seedAdmin(db *sql.DB, adminUsername, adminPasswordHash string) error {
	// Seed admin user.
	_, err := db.Exec(
		"INSERT OR IGNORE INTO users(username,password) VALUES(?,?)",
		adminUsername, adminPasswordHash,
	)
	if err != nil {
		return fmt.Errorf("seed admin: %w", err)
	}
	return nil
}

// StartupStep runs fn and logs its name and duration, so a slow start says
// which step it spent its time in. A failing step is logged too, with its
// error, before the error is returned.
func StartupStep(name string, fn func() error) error {
	start := time.Now()
	err := fn()
	ev := log.Info()
	if err != nil {
		ev = log.Error().Err(err)
	}
	ev.Str("step", name).Dur("took", time.Since(start)).Msg("startup step")
	return err
}

// Init runs an integrity check, creates tables, applies migrations, and seeds the admin user.
func Init(db *sql.DB, adminUsername, adminPasswordHash string) error {
	noErr := func(fn func(*sql.DB)) func() error { return func() error { fn(db); return nil } }
	steps := []struct {
		name string
		fn   func() error
	}{
		// The full integrity_check runs after start-up (integrity.go).
		{"quick_check", func() error {
			if err := QuickCheck(context.Background(), db); err != nil {
				return fmt.Errorf("integrity check failed: %w", err)
			}
			return nil
		}},
		{"create_schema", func() error { return createSchema(db) }},
		{"migrations", func() error { return applyColumnMigrations(db) }},
		{"post_migration_indexes", func() error { return createPostMigrationIndexes(db) }},
		{"backfill_proxy_logs", noErr(backfillProxyLogs)},
		{"seed_settings", noErr(seedDefaultSettings)},
		{"seed_admin", func() error { return seedAdmin(db, adminUsername, adminPasswordHash) }},
		// Update query planner statistics for optimal index usage.
		{"analyze", func() error {
			if _, err := db.Exec("ANALYZE"); err != nil {
				log.Warn().Err(err).Msg("ANALYZE failed (non-fatal)")
			}
			return nil
		}},
	}
	for _, s := range steps {
		if err := StartupStep(s.name, s.fn); err != nil {
			return err
		}
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
	_, err := ExportBlacklistsCounted(db, configDir)
	return err
}

// ExportCounts is what one export wrote to the DNS sinkhole's hosts file,
// counted while it was written: DNSEntries domain blacklist entries, and
// LeftOut entries the allowed list took out. Entries counts rows, so
// "*.example.com" and "example.com" are two, as on the Blacklists page.
type ExportCounts struct {
	DNSEntries int
	LeftOut    int
}

// ExportBlacklistsCounted is ExportBlacklistsToFiles that also says what the
// DNS sinkhole was given. COUNT(*) of the table counted the entries the
// allowed list leaves out as sent.
func ExportBlacklistsCounted(db *sql.DB, configDir string) (ExportCounts, error) {
	exportMu.Lock()
	defer exportMu.Unlock()
	var counts ExportCounts
	// 1. ip_blacklist.txt
	if err := exportLines(db, configDir+"/ip_blacklist.txt",
		"SELECT ip FROM ip_blacklist ORDER BY ip"); err != nil {
		return ExportCounts{}, err
	}
	// 2. ip_whitelist.txt
	if err := exportLines(db, configDir+"/ip_whitelist.txt",
		"SELECT ip FROM ip_whitelist ORDER BY ip"); err != nil {
		return ExportCounts{}, err
	}
	// The whitelist reader below filters on type='fqdn'; a row with any other
	// type would be listed but never applied. The CHECK makes that impossible
	// on migrated databases, and this refuses if one is ever reached anyway.
	var strayWhitelist int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM domain_whitelist WHERE type IS NOT 'fqdn'").Scan(&strayWhitelist); err != nil {
		return ExportCounts{}, fmt.Errorf("domain_whitelist type check: %w", err)
	}
	if strayWhitelist > 0 {
		return ExportCounts{}, fmt.Errorf("domain_whitelist holds %d row(s) whose type is not 'fqdn'; "+
			"nothing reads them; fix them before the lists can be exported", strayWhitelist)
	}
	// 3. domain_blacklist.txt (with whitelist exclusions)
	exclusions := loadWhitelistSet(db)
	if err := exportDomainBlacklist(db, configDir+"/domain_blacklist.txt", exclusions); err != nil {
		return ExportCounts{}, err
	}
	// 3b. Egress destination allowlist (default-deny mode): split by type into a
	// CIDR/IP list and a domain list that Squid reads as `dst` / `dstdomain`.
	// Refuse to export past a row the split does not understand. Both queries
	// below are equality tests, so an unrecognised type is silently dropped from
	// both files while the UI keeps listing it — an allowlist entry with no
	// effect and no error. On a pre-CHECK database this is the only guard
	// (SECURE-DOM-02).
	var strayTypes int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM dst_allowlist WHERE type NOT IN ('cidr','domain')").Scan(&strayTypes); err != nil {
		return ExportCounts{}, fmt.Errorf("dst_allowlist type check: %w", err)
	}
	if strayTypes > 0 {
		return ExportCounts{}, fmt.Errorf("dst_allowlist holds %d row(s) whose type is neither 'cidr' nor 'domain'; "+
			"they would reach neither enforcement file; fix them before the allowlist can be exported", strayTypes)
	}
	if err := exportLines(db, configDir+"/dst_allow_ip.txt",
		`SELECT entry FROM dst_allowlist WHERE type='cidr'
		 UNION
		 SELECT e.cidr AS entry
		 FROM egress_provider_entries e
		 JOIN egress_providers p ON p.id = e.provider_id
		 WHERE p.enabled = 1
		 ORDER BY 1`); err != nil {
		return ExportCounts{}, err
	}
	if err := exportLines(db, configDir+"/dst_allow_domain.txt",
		"SELECT entry FROM dst_allowlist WHERE type='domain' ORDER BY entry"); err != nil {
		return ExportCounts{}, err
	}
	// 3c. Manifest of the five lists Squid enforces, written after all of them
	// so the proxy can verify what it is about to load (SECURE-ARCH-01). A
	// failure here fails the export: the lists are on disk but not vouched for,
	// and the proxy will keep its previous copies until the next export.
	if err := writeListsManifest(configDir); err != nil {
		return ExportCounts{}, err
	}
	// 4. dnsmasq blocklist (hosts format, re-read on SIGHUP). Remove the legacy
	// conf-dir address= file so it doesn't double-load with stale, restart-only data.
	_ = os.Remove(configDir + "/dnsmasq.d/blocklist.conf")
	if err := writeDnsmasqBlocklist(db, configDir+"/dnsmasq.d/blocklist.hosts", exclusions, &counts); err != nil {
		// Not swallowed: the Squid lists above were written, so a domain added
		// now would be enforced by Squid and not by dnsmasq, and the caller
		// would be told the export succeeded. Returning the error makes a
		// partial export a reported one; the caller can see which half is stale.
		return ExportCounts{}, fmt.Errorf("dnsmasq blocklist not written (the Squid lists were): %w", err)
	}
	return counts, nil
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
	//
	// #nosec G304 — dir is filepath.Dir(path), and path is built by the caller
	// from the configured ConfigDir, never from request input. It is opened
	// read-only and never read: the handle exists only to fsync the directory.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func exportLines(db *sql.DB, path, query string) error {
	return streamList(db, path, query, func(w *bufio.Writer, v string) error {
		_, err := fmt.Fprintln(w, v)
		return err
	})
}

// streamList writes the rows of query to path through atomicWrite, one call
// of emit per value, as they are read. The lists used to be collected in a
// slice first, twice over for the domain blacklist (its file and the dnsmasq
// file), so the export held every entry in memory: 640,000 names on the
// test deployment, inside the backend's 128 MiB.
//
// Values that are empty, NULL or not lineSafe are skipped, as before. A row
// that cannot be read fails the write, so the previous file stays in place:
// collecting the rows ignored that error and published a short list.
func streamList(db *sql.DB, path, query string, emit func(w *bufio.Writer, v string) error) error {
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	unsafe := 0
	err = atomicWrite(path, func(f *os.File) error {
		w := bufio.NewWriter(f)
		for rows.Next() {
			var v string
			if rows.Scan(&v) != nil || v == "" {
				continue
			}
			if !lineSafe(v) {
				unsafe++
				continue
			}
			if err := emit(w, v); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read the rows of %s: %w", path, err)
		}
		return w.Flush()
	})
	reportUnsafe(path, unsafe)
	return err
}

// lineSafe reports whether v can be written as one line of a list file without
// being read back as more than one record: no whitespace and no control bytes.
// It is deliberately weaker than the syntax check the add endpoints apply, so
// an entry stored before that check existed is not silently dropped from
// enforcement; it removes only what could split a line.
func lineSafe(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; c <= ' ' || c == 0x7f {
			return false
		}
	}
	return v != ""
}

// LineSafe is lineSafe for the other writers of list files (the list download).
func LineSafe(v string) bool { return lineSafe(v) }

func reportUnsafe(path string, n int) {
	if n > 0 {
		log.Warn().Str("file", filepath.Base(path)).Int("rows", n).
			Msg("export: skipped rows containing whitespace or control characters; they would not be one list entry")
	}
}

// EnforcedDomain is the name the DNS sinkhole and Squid enforce for a stored
// domain blacklist entry: lower case, without a leading "*." or ".". Neither
// form covers subdomains here: dnsmasq gets an exact hosts entry, and the
// proxy's normalize_domain_lines (proxy/blacklist_watchdog.py) drops the same
// prefixes before Squid loads the name. dnsmasq used to get ".example.com"
// verbatim, a name no query matches, while Squid blocked example.com.
func EnforcedDomain(d string) string {
	d = strings.TrimPrefix(strings.ToLower(d), "*.")
	return strings.TrimLeft(d, ".")
}

// blockedOnAllowedQuery counts the blocked entries the export leaves out: those
// whose enforced name (EnforcedDomain) is on the allowed list. It is the
// export's rule, so the count the page shows is what the export did, and it
// reads no row it does not count:
//   - a lower-case entry is one of the forms the add, import and restore paths
//     accept for an allowed name n (n, *.n, .n, *..n), found through the
//     UNIQUE index on domain, four probes per allowed name;
//   - an entry with an upper-case letter (imports keep the feed's case) is
//     found through idx_domain_blacklist_mixed_case, which holds only those.
//
// The two halves are disjoint: the first matches only lower-case strings.
// Measured on 1,005,000 entries (5,000 of them mixed case) and 220 allowed
// names: one expression over every entry took 280 ms, this takes 2.3 ms.
const blockedOnAllowedQuery = `WITH allowed(n) AS (
	  SELECT DISTINCT ltrim(lower(domain), '.') FROM domain_whitelist WHERE type = 'fqdn')
	SELECT
	  (SELECT COUNT(*) FROM allowed a JOIN domain_blacklist b
	     ON b.domain IN (a.n, '*.' || a.n, '.' || a.n, '*..' || a.n))
	+ (SELECT COUNT(*) FROM domain_blacklist b INDEXED BY idx_domain_blacklist_mixed_case
	     WHERE b.domain != lower(b.domain)
	       AND ltrim(lower(CASE WHEN b.domain LIKE '*.%' THEN substr(b.domain, 3) ELSE b.domain END), '.')
	           IN (SELECT n FROM allowed))`

// BlockedOnAllowed is how many domain blacklist entries the allowed list takes
// out of the exported files.
func BlockedOnAllowed(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(blockedOnAllowedQuery).Scan(&n)
	return n, err
}

// loadWhitelistSet is the set of names the allowed list takes off the
// blacklist: a blocked entry whose EnforcedDomain is in it is not exported.
// Comparing the stored strings left "*.example.com", ".example.com" and
// "Example.com" enforced, as example.com, under an allowed example.com.
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
			set[EnforcedDomain(d)] = struct{}{}
		}
	}
	return set
}

func exportDomainBlacklist(db *sql.DB, path string, exclusions map[string]struct{}) error {
	return streamList(db, path, "SELECT domain FROM domain_blacklist ORDER BY domain", func(w *bufio.Writer, domain string) error {
		if _, excluded := exclusions[EnforcedDomain(domain)]; excluded {
			return nil
		}
		_, err := fmt.Fprintln(w, domain)
		return err
	})
}

// writeDnsmasqBlocklist writes the hosts file dnsmasq answers from.
//
// A hosts file is parsed by line: a value carrying a newline or a tab would be
// a second record, and dnsmasq would answer it. streamList skips it whatever
// the write path let in (audit: domain-newline-into-hosts-file).
//
// Emit a hosts-format file (consumed via dnsmasq addn-hosts) rather than
// `address=` directives in a conf-dir file: dnsmasq RE-READS addn-hosts on
// SIGHUP, so a blacklist change applies on reload instead of needing a full
// DNS restart. No timestamp header: an unchanged blocklist produces a byte-
// identical file, avoiding a pointless full re-parse on every export.
// (Trade-off: hosts entries are exact-match, not the `/domain/` subdomain
// wildcard; the imported lists are explicit domains, so this matches them.)
//
// counts receives the entries written and those the allowed list left out. A
// failed write leaves them partial; the caller reports the error, not them.
func writeDnsmasqBlocklist(db *sql.DB, path string, exclusions map[string]struct{}, counts *ExportCounts) error {
	*counts = ExportCounts{}
	return streamList(db, path, "SELECT domain FROM domain_blacklist ORDER BY domain", func(w *bufio.Writer, domain string) error {
		// The hosts file gets the name dnsmasq is to answer, the same one
		// Squid enforces (EnforcedDomain).
		d := EnforcedDomain(domain)
		if d == "" {
			return nil
		}
		if _, excluded := exclusions[d]; excluded {
			counts.LeftOut++
			return nil
		}
		if _, err := fmt.Fprintf(w, "0.0.0.0 %s\n:: %s\n", d, d); err != nil {
			return err
		}
		counts.DNSEntries++
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
