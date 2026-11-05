package database

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
)

// Provenance of list entries (schema version 3, migrate.go).
//
// list_sources holds one row for each place entries came from, and every list
// table carries source_id, the row that added the entry. Before version 3 the
// only trace was a description such as "Imported on 2026-10-25", which repeated
// the date column and named no list, so an imported list could not be told
// apart from another or removed as a whole. Rows that predate it keep
// source_id NULL: their source was not recorded, and none is invented.
//
// Kinds:
//   - url: a list fetched from a URL (an import, a Popular list, the
//     auto-refresh worker). Keyed by the URL, so importing or refreshing the
//     same list again adds to the same source; label is the Popular list name.
//   - manual: entries added one at a time. One source per list.
//   - geo: a country's address blocks. Keyed by the country code.
//   - paste: a list pasted into the import form. A new source each time.
//   - restore: a configuration restore. A new source each time.
//   - preset: a named group of common services added in one request
//     (handlers/presets.go). Keyed by the preset's id, so adding it again adds
//     to the same source; label is its name ("Common services: Docker").
//     Schema version 9 added it.
//
// An entry keeps the source that added it first (source_id); every other
// source that lists it is a row of <list>_sources (entry_sources.go). Removing
// a source removes only the entries no other source lists: the others are
// given one of their other sources.
const (
	SourceURL     = "url"
	SourceManual  = "manual"
	SourceGeo     = "geo"
	SourcePaste   = "paste"
	SourceRestore = "restore"
	SourcePreset  = "preset"
	// SourceUnrecorded is not stored: it names the entries whose source_id is
	// NULL in a listing.
	SourceUnrecorded = "unrecorded"
)

// sourceListQueries holds every statement that names a list table, one set
// per table, each written out, so no table name is ever built from input.
type sourceListQueries struct {
	summary          string
	anyBySource      string // args: source, source
	deleteBySource   string
	deleteUnrecorded string
	// promote gives the entries whose source_id is the source being removed
	// (promoteUnrecorded: NULL) one of their other sources instead, and
	// dropPromoted then deletes the row of the source each one was given.
	promote           string
	promoteUnrecorded string
	dropPromoted      string
	unlinkSource      string
	link              string // args: source, value, source (LinkStatement)
}

var sourceLists = map[string]sourceListQueries{
	"ip_blacklist": {
		summary: `SELECT source_id, COUNT(*), COALESCE(MIN(d),''), COALESCE(MAX(d),'') FROM (
			SELECT source_id, added_date AS d FROM ip_blacklist
			UNION ALL SELECT source_id, added_date FROM ip_blacklist_sources) GROUP BY source_id`,
		anyBySource: `SELECT COUNT(*) FROM (SELECT 1 FROM ip_blacklist WHERE source_id = ?
			UNION ALL SELECT 1 FROM ip_blacklist_sources WHERE source_id = ? LIMIT 1)`,
		deleteBySource:   "DELETE FROM ip_blacklist WHERE source_id = ?",
		deleteUnrecorded: "DELETE FROM ip_blacklist WHERE source_id IS NULL",
		promote: `UPDATE ip_blacklist SET source_id = (SELECT MIN(x.source_id) FROM ip_blacklist_sources x WHERE x.entry_id = ip_blacklist.id AND x.source_id <> ip_blacklist.source_id)
			WHERE source_id = ? AND EXISTS (SELECT 1 FROM ip_blacklist_sources x WHERE x.entry_id = ip_blacklist.id AND x.source_id <> ip_blacklist.source_id)`,
		promoteUnrecorded: `UPDATE ip_blacklist SET source_id = (SELECT MIN(x.source_id) FROM ip_blacklist_sources x WHERE x.entry_id = ip_blacklist.id)
			WHERE source_id IS NULL AND EXISTS (SELECT 1 FROM ip_blacklist_sources x WHERE x.entry_id = ip_blacklist.id)`,
		dropPromoted: `DELETE FROM ip_blacklist_sources WHERE EXISTS (SELECT 1 FROM ip_blacklist t
			WHERE t.id = ip_blacklist_sources.entry_id AND t.source_id = ip_blacklist_sources.source_id)`,
		unlinkSource: "DELETE FROM ip_blacklist_sources WHERE source_id = ?",
		link: `INSERT OR IGNORE INTO ip_blacklist_sources(entry_id, source_id)
			SELECT id, ? FROM ip_blacklist WHERE ip = ? AND (source_id IS NULL OR source_id <> ?)`,
	},
	"domain_blacklist": {
		summary: `SELECT source_id, COUNT(*), COALESCE(MIN(d),''), COALESCE(MAX(d),'') FROM (
			SELECT source_id, added_date AS d FROM domain_blacklist
			UNION ALL SELECT source_id, added_date FROM domain_blacklist_sources) GROUP BY source_id`,
		anyBySource: `SELECT COUNT(*) FROM (SELECT 1 FROM domain_blacklist WHERE source_id = ?
			UNION ALL SELECT 1 FROM domain_blacklist_sources WHERE source_id = ? LIMIT 1)`,
		deleteBySource:   "DELETE FROM domain_blacklist WHERE source_id = ?",
		deleteUnrecorded: "DELETE FROM domain_blacklist WHERE source_id IS NULL",
		promote: `UPDATE domain_blacklist SET source_id = (SELECT MIN(x.source_id) FROM domain_blacklist_sources x WHERE x.entry_id = domain_blacklist.id AND x.source_id <> domain_blacklist.source_id)
			WHERE source_id = ? AND EXISTS (SELECT 1 FROM domain_blacklist_sources x WHERE x.entry_id = domain_blacklist.id AND x.source_id <> domain_blacklist.source_id)`,
		promoteUnrecorded: `UPDATE domain_blacklist SET source_id = (SELECT MIN(x.source_id) FROM domain_blacklist_sources x WHERE x.entry_id = domain_blacklist.id)
			WHERE source_id IS NULL AND EXISTS (SELECT 1 FROM domain_blacklist_sources x WHERE x.entry_id = domain_blacklist.id)`,
		dropPromoted: `DELETE FROM domain_blacklist_sources WHERE EXISTS (SELECT 1 FROM domain_blacklist t
			WHERE t.id = domain_blacklist_sources.entry_id AND t.source_id = domain_blacklist_sources.source_id)`,
		unlinkSource: "DELETE FROM domain_blacklist_sources WHERE source_id = ?",
		link: `INSERT OR IGNORE INTO domain_blacklist_sources(entry_id, source_id)
			SELECT id, ? FROM domain_blacklist WHERE domain = ? AND (source_id IS NULL OR source_id <> ?)`,
	},
	"ip_whitelist": {
		summary: `SELECT source_id, COUNT(*), COALESCE(MIN(d),''), COALESCE(MAX(d),'') FROM (
			SELECT source_id, added_date AS d FROM ip_whitelist
			UNION ALL SELECT source_id, added_date FROM ip_whitelist_sources) GROUP BY source_id`,
		anyBySource: `SELECT COUNT(*) FROM (SELECT 1 FROM ip_whitelist WHERE source_id = ?
			UNION ALL SELECT 1 FROM ip_whitelist_sources WHERE source_id = ? LIMIT 1)`,
		deleteBySource:   "DELETE FROM ip_whitelist WHERE source_id = ?",
		deleteUnrecorded: "DELETE FROM ip_whitelist WHERE source_id IS NULL",
		promote: `UPDATE ip_whitelist SET source_id = (SELECT MIN(x.source_id) FROM ip_whitelist_sources x WHERE x.entry_id = ip_whitelist.id AND x.source_id <> ip_whitelist.source_id)
			WHERE source_id = ? AND EXISTS (SELECT 1 FROM ip_whitelist_sources x WHERE x.entry_id = ip_whitelist.id AND x.source_id <> ip_whitelist.source_id)`,
		promoteUnrecorded: `UPDATE ip_whitelist SET source_id = (SELECT MIN(x.source_id) FROM ip_whitelist_sources x WHERE x.entry_id = ip_whitelist.id)
			WHERE source_id IS NULL AND EXISTS (SELECT 1 FROM ip_whitelist_sources x WHERE x.entry_id = ip_whitelist.id)`,
		dropPromoted: `DELETE FROM ip_whitelist_sources WHERE EXISTS (SELECT 1 FROM ip_whitelist t
			WHERE t.id = ip_whitelist_sources.entry_id AND t.source_id = ip_whitelist_sources.source_id)`,
		unlinkSource: "DELETE FROM ip_whitelist_sources WHERE source_id = ?",
		link: `INSERT OR IGNORE INTO ip_whitelist_sources(entry_id, source_id)
			SELECT id, ? FROM ip_whitelist WHERE ip = ? AND (source_id IS NULL OR source_id <> ?)`,
	},
	"domain_whitelist": {
		summary: `SELECT source_id, COUNT(*), COALESCE(MIN(d),''), COALESCE(MAX(d),'') FROM (
			SELECT source_id, added_date AS d FROM domain_whitelist
			UNION ALL SELECT source_id, added_date FROM domain_whitelist_sources) GROUP BY source_id`,
		anyBySource: `SELECT COUNT(*) FROM (SELECT 1 FROM domain_whitelist WHERE source_id = ?
			UNION ALL SELECT 1 FROM domain_whitelist_sources WHERE source_id = ? LIMIT 1)`,
		deleteBySource:   "DELETE FROM domain_whitelist WHERE source_id = ?",
		deleteUnrecorded: "DELETE FROM domain_whitelist WHERE source_id IS NULL",
		promote: `UPDATE domain_whitelist SET source_id = (SELECT MIN(x.source_id) FROM domain_whitelist_sources x WHERE x.entry_id = domain_whitelist.id AND x.source_id <> domain_whitelist.source_id)
			WHERE source_id = ? AND EXISTS (SELECT 1 FROM domain_whitelist_sources x WHERE x.entry_id = domain_whitelist.id AND x.source_id <> domain_whitelist.source_id)`,
		promoteUnrecorded: `UPDATE domain_whitelist SET source_id = (SELECT MIN(x.source_id) FROM domain_whitelist_sources x WHERE x.entry_id = domain_whitelist.id)
			WHERE source_id IS NULL AND EXISTS (SELECT 1 FROM domain_whitelist_sources x WHERE x.entry_id = domain_whitelist.id)`,
		dropPromoted: `DELETE FROM domain_whitelist_sources WHERE EXISTS (SELECT 1 FROM domain_whitelist t
			WHERE t.id = domain_whitelist_sources.entry_id AND t.source_id = domain_whitelist_sources.source_id)`,
		unlinkSource: "DELETE FROM domain_whitelist_sources WHERE source_id = ?",
		link: `INSERT OR IGNORE INTO domain_whitelist_sources(entry_id, source_id)
			SELECT id, ? FROM domain_whitelist WHERE domain = ? AND (source_id IS NULL OR source_id <> ?)`,
	},
}

// ErrUnknownList is returned for a list that has no provenance.
var ErrUnknownList = errors.New("unknown list")

// IsSourceList reports whether list is a table whose entries carry a source.
func IsSourceList(list string) bool {
	_, ok := sourceLists[list]
	return ok
}

// execQuerier is what both *sql.DB and *sql.Tx offer.
type execQuerier interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// KeyedSource returns the id of list's source of this kind and key (a URL, a
// country code, a preset id, or "" for manual), creating it on first use. A non-empty label
// replaces the stored one, so a Popular list keeps the name it was last
// imported under.
func KeyedSource(q execQuerier, list, kind, key, label string) (int64, error) {
	if !IsSourceList(list) {
		return 0, ErrUnknownList
	}
	if kind != SourceURL && kind != SourceManual && kind != SourceGeo && kind != SourcePreset {
		return 0, fmt.Errorf("source kind %q is not keyed", kind)
	}
	if _, err := q.Exec(
		"INSERT OR IGNORE INTO list_sources(list, kind, source, label) VALUES(?,?,?,?)",
		list, kind, key, label); err != nil {
		return 0, fmt.Errorf("record source: %w", err)
	}
	if label != "" {
		if _, err := q.Exec(
			"UPDATE list_sources SET label = ? WHERE list = ? AND kind = ? AND source = ?",
			label, list, kind, key); err != nil {
			return 0, fmt.Errorf("label source: %w", err)
		}
	}
	var id int64
	if err := q.QueryRow(
		"SELECT id FROM list_sources WHERE list = ? AND kind = ? AND source = ?",
		list, kind, key).Scan(&id); err != nil {
		return 0, fmt.Errorf("read source: %w", err)
	}
	return id, nil
}

// NewSource records a source that is one event (a pasted list, a restore).
func NewSource(q execQuerier, list, kind, label string) (int64, error) {
	if !IsSourceList(list) {
		return 0, ErrUnknownList
	}
	if kind != SourcePaste && kind != SourceRestore {
		return 0, fmt.Errorf("source kind %q is keyed, not one event", kind)
	}
	res, err := q.Exec("INSERT INTO list_sources(list, kind, source, label) VALUES(?,?,'',?)", list, kind, label)
	if err != nil {
		return 0, fmt.Errorf("record source: %w", err)
	}
	return res.LastInsertId()
}

// DropSourceIfEmpty removes a source that no entry references, such as a
// pasted list whose every line was already listed. A source that gained
// entries in the meantime stays: the foreign key refuses the delete and the
// error is ignored on purpose.
func DropSourceIfEmpty(db *sql.DB, list string, id int64) {
	q, ok := sourceLists[list]
	if !ok || id <= 0 {
		return
	}
	var n int
	if err := db.QueryRow(q.anyBySource, id, id).Scan(&n); err != nil || n > 0 {
		return
	}
	_, _ = db.Exec("DELETE FROM list_sources WHERE id = ? AND list = ?", id, list)
}

// SourceSummary is one row of the "where the entries came from" table.
type SourceSummary struct {
	// ID is null for the entries whose source was not recorded.
	ID      *int64 `json:"id"`
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	Label   string `json:"label"`
	Entries int    `json:"entries"`
	// Scope is "global" (every client) or "groups" (only the client groups
	// that use the source, client_groups.go); empty for unrecorded entries.
	Scope      string `json:"scope,omitempty"`
	FirstAdded string `json:"first_added"`
	LastAdded  string `json:"last_added"`
	// The last refresh of a url source (workers/list_sync.go): when (UTC),
	// "ok", "held" or "failed", and what it came to. Empty until one ran.
	RefreshedAt   string `json:"refreshed_at,omitempty"`
	RefreshStatus string `json:"refresh_status,omitempty"`
	RefreshDetail string `json:"refresh_detail,omitempty"`
}

// ListSources returns the sources that have entries in list, most recently
// added first, with the entries whose source was not recorded last. The counts
// and dates are those of the entries, not of the source rows: a source whose
// entries were all removed is not listed.
func ListSources(db *sql.DB, list string) ([]SourceSummary, error) {
	q, ok := sourceLists[list]
	if !ok {
		return nil, ErrUnknownList
	}
	meta := map[int64]SourceSummary{}
	srows, err := db.Query("SELECT id, kind, source, label, scope, COALESCE(refreshed_at,''), COALESCE(refresh_status,''), COALESCE(refresh_detail,'') FROM list_sources WHERE list = ?", list)
	if err != nil {
		return nil, err
	}
	for srows.Next() {
		var s SourceSummary
		var id int64
		if err := srows.Scan(&id, &s.Kind, &s.Source, &s.Label, &s.Scope, &s.RefreshedAt, &s.RefreshStatus, &s.RefreshDetail); err != nil {
			srows.Close()
			return nil, err
		}
		meta[id] = s
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		return nil, err
	}

	rows, err := db.Query(q.summary)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SourceSummary
	var unrecorded *SourceSummary
	for rows.Next() {
		var id sql.NullInt64
		var n int
		var first, last string
		if err := rows.Scan(&id, &n, &first, &last); err != nil {
			return nil, err
		}
		if !id.Valid {
			unrecorded = &SourceSummary{Kind: SourceUnrecorded, Entries: n, FirstAdded: first, LastAdded: last}
			continue
		}
		s, known := meta[id.Int64]
		if !known {
			// The foreign key makes this unreachable; say so rather than
			// inventing a kind.
			s = SourceSummary{Kind: SourceUnrecorded}
		}
		v := id.Int64
		s.ID, s.Entries, s.FirstAdded, s.LastAdded = &v, n, first, last
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].LastAdded != out[j].LastAdded {
			return out[i].LastAdded > out[j].LastAdded
		}
		return *out[i].ID > *out[j].ID
	})
	if unrecorded != nil {
		out = append(out, *unrecorded)
	}
	if out == nil {
		out = []SourceSummary{}
	}
	return out, nil
}

// RemoveSource removes a source from list, in one transaction: the entries no
// other source lists go, the others are given one of their other sources and
// stay. It returns how many went and how many stayed. sourceID 0 means the
// entries whose source was not recorded. The caller exports the lists
// afterwards, so the proxy and the DNS sinkhole stop enforcing what went.
func RemoveSource(db *sql.DB, list string, sourceID int64) (removed, kept int64, err error) {
	q, ok := sourceLists[list]
	if !ok {
		return 0, 0, ErrUnknownList
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	var res sql.Result
	if sourceID == 0 {
		res, err = tx.Exec(q.promoteUnrecorded)
	} else {
		res, err = tx.Exec(q.promote, sourceID)
	}
	if err != nil {
		return 0, 0, err
	}
	kept, _ = res.RowsAffected()
	if _, err := tx.Exec(q.dropPromoted); err != nil {
		return 0, 0, err
	}
	if sourceID == 0 {
		res, err = tx.Exec(q.deleteUnrecorded)
	} else {
		res, err = tx.Exec(q.deleteBySource, sourceID)
	}
	if err != nil {
		return 0, 0, err
	}
	removed, _ = res.RowsAffected()
	if sourceID != 0 {
		if _, err := tx.Exec(q.unlinkSource, sourceID); err != nil {
			return 0, 0, err
		}
		if _, err := tx.Exec("DELETE FROM list_sources WHERE id = ? AND list = ?", sourceID, list); err != nil {
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return removed, kept, nil
}
