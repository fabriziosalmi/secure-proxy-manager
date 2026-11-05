package database

import (
	"database/sql"
	"fmt"

	"github.com/rs/zerolog/log"
)

// The other sources of a list entry (schema version 10).
//
// An entry is stored once (its value is UNIQUE) with source_id, the source
// that added it first. Every other source that lists it was dropped: a second
// list that held the same name, or the same name added by hand, left no
// trace, and removing the first source removed the entry while the second
// list, or the person who added it by hand, still wanted it blocked. A pasted
// list is never downloaded again, so the gap stayed.
//
// <list>_sources holds those other sources, one row per entry and source, and
// never the entry's own source_id. An entry goes only when no source is left:
// removing its source_id first promotes one of these (RemoveSource, and the
// refresh in workers/list_sync.go). A row goes with its entry (ON DELETE
// CASCADE); a source with rows cannot be deleted while they exist (no
// cascade), so a source is never dropped from under an entry by accident.

// entrySourceTables is each list table with its value column and its sources
// table, written out so no table name is built from input.
var entrySourceTables = []struct{ list, col, sources SQLText }{
	{"ip_blacklist", "ip", "ip_blacklist_sources"},
	{"domain_blacklist", "domain", "domain_blacklist_sources"},
	{"ip_whitelist", "ip", "ip_whitelist_sources"},
	{"domain_whitelist", "domain", "domain_whitelist_sources"},
}

// migrateEntrySources creates the four sources tables and records version 10.
// Nothing is filled in: which other sources listed an entry was never stored.
func migrateEntrySources(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	for _, t := range entrySourceTables {
		// #nosec G202 -- names are constants of entrySourceTables
		steps := []SQLText{
			"CREATE TABLE IF NOT EXISTS " + t.sources + ` (
				entry_id INTEGER NOT NULL REFERENCES ` + t.list + `(id) ON DELETE CASCADE,
				source_id INTEGER NOT NULL REFERENCES list_sources(id),
				added_date TEXT DEFAULT (datetime('now')),
				PRIMARY KEY (entry_id, source_id)
			) WITHOUT ROWID`,
			"CREATE INDEX IF NOT EXISTS idx_" + t.sources + "_source ON " + t.sources + "(source_id, entry_id)",
		}
		for _, s := range steps {
			if _, err := tx.Exec(string(s)); err != nil {
				return fmt.Errorf("%s: %w", t.sources, err)
			}
		}
	}
	if _, err := tx.Exec("PRAGMA user_version = 10"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Info().Int("version", 10).Msg("schema migrated: a list entry records every source that lists it")
	return nil
}

// LinkStatement is the statement that records sourceID as another source of
// an entry already on list: arguments sourceID, the value, sourceID. It does
// nothing when the value is not listed, or when sourceID is already its
// source. Prepared by the import paths, which write many values at once.
func LinkStatement(list string) (string, error) {
	q, ok := sourceLists[list]
	if !ok {
		return "", ErrUnknownList
	}
	return q.link, nil
}

// LinkListed records sourceID as another source of value on list, and says
// whether it did (false: not listed, or sourceID already one of its sources).
func LinkListed(q execQuerier, list, value string, sourceID int64) (bool, error) {
	stmt, err := LinkStatement(list)
	if err != nil {
		return false, err
	}
	res, err := q.Exec(stmt, sourceID, value, sourceID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// LinkAllListed is LinkListed for many values in one transaction, for an
// import whose lines were already on the list. It returns how many it linked.
func LinkAllListed(db *sql.DB, list string, sourceID int64, values []string) (int, error) {
	if len(values) == 0 || sourceID <= 0 {
		return 0, nil
	}
	stmtText, err := LinkStatement(list)
	if err != nil {
		return 0, err
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	stmt, err := tx.Prepare(stmtText)
	if err != nil {
		return 0, err
	}
	defer stmt.Close() //nolint:errcheck
	linked := 0
	for _, v := range values {
		res, err := stmt.Exec(sourceID, v, sourceID)
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			linked++
		}
	}
	return linked, tx.Commit()
}
