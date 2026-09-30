package database

import (
	"database/sql"
	"fmt"

	"github.com/rs/zerolog/log"
)

// schemaVersion is the value PRAGMA user_version holds once every step below
// has run. Version 1 is everything that came before versioning existed: the
// idempotent ADD COLUMN list in Init, which still runs on every start. Steps
// numbered 2 and up run exactly once, in a transaction, and record themselves.
const schemaVersion = 2

// applyVersionedMigrations runs the steps a database has not seen yet.
//
// ADD COLUMN can be replayed safely, but a CHECK constraint, a type change or
// any other table rebuild cannot, and CREATE TABLE IF NOT EXISTS is a no-op for
// a table that already exists. Without a recorded version those changes had no
// place to run once, which is why dst_allowlist.type carried its CHECK on new
// databases only (SECURE-DOM-02, SECURE-DOM-03).
func applyVersionedMigrations(db *sql.DB) error {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if v >= schemaVersion {
		return nil
	}
	if v < 2 {
		if err := migrateTypeConstraints(db); err != nil {
			return fmt.Errorf("schema version 2: %w", err)
		}
	}
	return nil
}

// migrateTypeConstraints gives databases created before the CHECK constraints
// existed the same constraints a new database gets, by rebuilding
// dst_allowlist and domain_whitelist (create, copy, drop, rename) in one
// transaction that also records the new version.
//
// Rows that already violate the constraint are repaired or dropped rather than
// failing start-up, and each case is logged with a count:
//   - dst_allowlist: the type is re-derived from the entry (an address or CIDR
//     is 'cidr', anything else 'domain'), the same rule the API applies on add.
//     Such a row was listed but reached neither enforcement file.
//   - domain_whitelist: only 'fqdn' is read by anything, so other rows (the old
//     url-regex type) were inert; they are not carried over.
func migrateTypeConstraints(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	var repaired, dropped int
	if err := tx.QueryRow(
		"SELECT COUNT(*) FROM dst_allowlist WHERE type NOT IN ('cidr','domain') OR type IS NULL").Scan(&repaired); err != nil {
		return fmt.Errorf("count dst_allowlist rows: %w", err)
	}
	if err := tx.QueryRow(
		"SELECT COUNT(*) FROM domain_whitelist WHERE type IS NOT NULL AND type != 'fqdn'").Scan(&dropped); err != nil {
		return fmt.Errorf("count domain_whitelist rows: %w", err)
	}

	steps := []string{
		`CREATE TABLE dst_allowlist_v2 (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			entry TEXT UNIQUE NOT NULL,
			type TEXT NOT NULL DEFAULT 'domain' CHECK (type IN ('cidr','domain')),
			description TEXT,
			added_date TEXT DEFAULT (datetime('now'))
		)`,
		`INSERT INTO dst_allowlist_v2(id, entry, type, description, added_date)
		 SELECT id, entry,
		        CASE WHEN type IN ('cidr','domain') THEN type
		             WHEN entry GLOB '*[/:]*' OR entry GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' THEN 'cidr'
		             ELSE 'domain' END,
		        description, added_date
		 FROM dst_allowlist`,
		`DROP TABLE dst_allowlist`,
		`ALTER TABLE dst_allowlist_v2 RENAME TO dst_allowlist`,

		`CREATE TABLE domain_whitelist_v2 (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT UNIQUE NOT NULL,
			type TEXT NOT NULL DEFAULT 'fqdn' CHECK (type IN ('fqdn')),
			description TEXT,
			added_date TEXT DEFAULT (datetime('now'))
		)`,
		`INSERT INTO domain_whitelist_v2(id, domain, type, description, added_date)
		 SELECT id, domain, 'fqdn', description, added_date
		 FROM domain_whitelist WHERE type IS NULL OR type = 'fqdn'`,
		`DROP TABLE domain_whitelist`,
		`ALTER TABLE domain_whitelist_v2 RENAME TO domain_whitelist`,

		fmt.Sprintf("PRAGMA user_version = %d", 2),
	}
	for _, s := range steps {
		if _, err := tx.Exec(s); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if repaired > 0 {
		log.Warn().Int("rows", repaired).Msg("schema migration: dst_allowlist rows with an unrecognised type were re-derived from their entry")
	}
	if dropped > 0 {
		log.Warn().Int("rows", dropped).Msg("schema migration: domain_whitelist rows with a type other than 'fqdn' were not carried over (nothing read them)")
	}
	log.Info().Int("version", 2).Msg("schema migrated")
	return nil
}
