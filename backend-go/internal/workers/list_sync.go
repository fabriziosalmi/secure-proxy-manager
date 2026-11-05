package workers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/listentry"
)

// The refresh of the blocked lists, as a sync with each feed.
//
// Every list imported from a URL that still has entries (a Popular list, an
// address typed in the import form), the built-in feeds and the URLs in
// ip_blacklist_urls and domain_blacklist_urls are downloaded again. A run
// reads every feed of a list first, then for each feed that answered:
//
//   - the entries its source added that it no longer lists go: to another
//     feed read in the same run that still lists them (the entry moves to
//     that source), or out of the list;
//   - then the entries it lists that the list lacks are added under its
//     source, so a removal frees room under the domain limit for an addition
//     of the same run.
//
// Nothing is removed from a list when:
//
//   - the feed answered with no entry, or with fewer than half the entries
//     its source holds (held: a truncated or replaced file is likelier than a
//     feed dropping half its threats at once);
//   - any feed of that list could not be downloaded in this run (deferred):
//     an entry that feed lists may belong to another source, which added it
//     first, and removing it would leave a gap until the feed comes back.
//
// Entries added by hand, from a paste, a country, a preset or a restore are
// never compared with a feed: only a url source's own entries are. A line of
// a feed is read with listentry.Parse, as the import reads it, so an entry an
// import added is the entry the refresh compares. The refresh used to only
// add, so an entry a feed dropped stayed blocked for ever, and a list imported
// from a URL was never downloaded again.

// syncList holds the statements of one list, each written out, so no table
// name is built from input. Every write covers one window of at most
// syncChunk rows: a range of a feed's entries for an addition, a range of one
// source's ids (on the (source_id, id) index) for a move or a removal. The
// bounds of a window are read first, without the write lock, so a transaction
// holds the lock for its window alone (list_sync_perf_test.go).
type syncList struct {
	kind        listentry.Kind
	feedSources string // the url sources with entries, for feedURLs
	count       string
	bySource    string
	candidates  string
	insertNew   string
	idBound     string // the id syncChunk rows of a source after a given id
	idLast      string // the last id of a source after a given id
	moveStale   string
	deleteStale string
	// The other sources of an entry (database/entry_sources.go): linkNew
	// records the feed's source on the entries it lists that another source
	// added; promoteStale gives an entry the feed no longer lists one of its
	// other sources, instead of removing it; unlinkStale drops the feed's
	// source from the entries it no longer lists; dropPromoted deletes the
	// row of the source an entry was given.
	linkNew      string
	promoteStale string
	unlinkStale  string
	dropPromoted string
}

var syncLists = map[string]syncList{
	"ip_blacklist": {
		kind: listentry.IP,
		feedSources: `SELECT s.source FROM list_sources s
			WHERE s.list = 'ip_blacklist' AND s.kind = 'url'
			AND (EXISTS (SELECT 1 FROM ip_blacklist e WHERE e.source_id = s.id)
				OR EXISTS (SELECT 1 FROM ip_blacklist_sources x WHERE x.source_id = s.id)) ORDER BY s.id`,
		count:    `SELECT COUNT(*) FROM ip_blacklist`,
		bySource: `SELECT (SELECT COUNT(*) FROM ip_blacklist WHERE source_id = ?) + (SELECT COUNT(*) FROM ip_blacklist_sources WHERE source_id = ?)`,
		candidates: `SELECT COUNT(*) FROM temp.refresh_feed f WHERE f.source_id = ?
			AND NOT EXISTS (SELECT 1 FROM ip_blacklist t WHERE t.ip = f.entry)`,
		insertNew: `INSERT OR IGNORE INTO ip_blacklist (ip, description, source_id)
			SELECT f.entry, '', ? FROM temp.refresh_feed f
			WHERE f.source_id = ? AND f.entry > ? AND f.entry <= ?
			AND NOT EXISTS (SELECT 1 FROM ip_blacklist t WHERE t.ip = f.entry) LIMIT ?`,
		idBound: `SELECT id FROM ip_blacklist INDEXED BY idx_ip_blacklist_source_id
			WHERE source_id = ? AND id > ? ORDER BY id LIMIT 1 OFFSET ?`,
		idLast: `SELECT MAX(id) FROM ip_blacklist INDEXED BY idx_ip_blacklist_source_id
			WHERE source_id = ? AND id > ?`,
		moveStale: `UPDATE ip_blacklist
			SET source_id = (SELECT MIN(f.source_id) FROM temp.refresh_feed f WHERE f.entry = ip_blacklist.ip AND f.source_id <> ?)
			WHERE id IN (SELECT d.id FROM ip_blacklist d INDEXED BY idx_ip_blacklist_source_id
				WHERE d.source_id = ? AND d.id > ? AND d.id <= ?
				AND NOT EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.source_id = ? AND f.entry = d.ip)
				AND EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.entry = d.ip AND f.source_id <> ?))`,
		deleteStale: `DELETE FROM ip_blacklist WHERE id IN (SELECT d.id FROM ip_blacklist d INDEXED BY idx_ip_blacklist_source_id
			WHERE d.source_id = ? AND d.id > ? AND d.id <= ?
			AND NOT EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.source_id = ? AND f.entry = d.ip))`,
		linkNew: `INSERT OR IGNORE INTO ip_blacklist_sources (entry_id, source_id)
			SELECT t.id, ? FROM temp.refresh_feed f JOIN ip_blacklist t ON t.ip = f.entry
			WHERE f.source_id = ? AND f.entry > ? AND f.entry <= ?
			AND (t.source_id IS NULL OR t.source_id <> ?)`,
		promoteStale: `UPDATE ip_blacklist
			SET source_id = (SELECT MIN(x.source_id) FROM ip_blacklist_sources x WHERE x.entry_id = ip_blacklist.id AND x.source_id <> ip_blacklist.source_id)
			WHERE id IN (SELECT d.id FROM ip_blacklist d INDEXED BY idx_ip_blacklist_source_id
				WHERE d.source_id = ? AND d.id > ? AND d.id <= ?
				AND NOT EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.source_id = ? AND f.entry = d.ip)
				AND EXISTS (SELECT 1 FROM ip_blacklist_sources x WHERE x.entry_id = d.id AND x.source_id <> d.source_id))`,
		unlinkStale: `DELETE FROM ip_blacklist_sources WHERE source_id = ? AND entry_id IN (
			SELECT x.entry_id FROM ip_blacklist_sources x JOIN ip_blacklist t ON t.id = x.entry_id
			WHERE x.source_id = ? AND NOT EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.source_id = ? AND f.entry = t.ip))`,
		dropPromoted: `DELETE FROM ip_blacklist_sources WHERE EXISTS (SELECT 1 FROM ip_blacklist t
			WHERE t.id = ip_blacklist_sources.entry_id AND t.source_id = ip_blacklist_sources.source_id)`,
	},
	"domain_blacklist": {
		kind: listentry.Domain,
		feedSources: `SELECT s.source FROM list_sources s
			WHERE s.list = 'domain_blacklist' AND s.kind = 'url'
			AND (EXISTS (SELECT 1 FROM domain_blacklist e WHERE e.source_id = s.id)
				OR EXISTS (SELECT 1 FROM domain_blacklist_sources x WHERE x.source_id = s.id)) ORDER BY s.id`,
		count:    `SELECT COUNT(*) FROM domain_blacklist`,
		bySource: `SELECT (SELECT COUNT(*) FROM domain_blacklist WHERE source_id = ?) + (SELECT COUNT(*) FROM domain_blacklist_sources WHERE source_id = ?)`,
		candidates: `SELECT COUNT(*) FROM temp.refresh_feed f WHERE f.source_id = ?
			AND NOT EXISTS (SELECT 1 FROM domain_blacklist t WHERE t.domain = f.entry)`,
		insertNew: `INSERT OR IGNORE INTO domain_blacklist (domain, description, source_id)
			SELECT f.entry, '', ? FROM temp.refresh_feed f
			WHERE f.source_id = ? AND f.entry > ? AND f.entry <= ?
			AND NOT EXISTS (SELECT 1 FROM domain_blacklist t WHERE t.domain = f.entry) LIMIT ?`,
		idBound: `SELECT id FROM domain_blacklist INDEXED BY idx_domain_blacklist_source_id
			WHERE source_id = ? AND id > ? ORDER BY id LIMIT 1 OFFSET ?`,
		idLast: `SELECT MAX(id) FROM domain_blacklist INDEXED BY idx_domain_blacklist_source_id
			WHERE source_id = ? AND id > ?`,
		moveStale: `UPDATE domain_blacklist
			SET source_id = (SELECT MIN(f.source_id) FROM temp.refresh_feed f WHERE f.entry = domain_blacklist.domain AND f.source_id <> ?)
			WHERE id IN (SELECT d.id FROM domain_blacklist d INDEXED BY idx_domain_blacklist_source_id
				WHERE d.source_id = ? AND d.id > ? AND d.id <= ?
				AND NOT EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.source_id = ? AND f.entry = d.domain)
				AND EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.entry = d.domain AND f.source_id <> ?))`,
		deleteStale: `DELETE FROM domain_blacklist WHERE id IN (SELECT d.id FROM domain_blacklist d INDEXED BY idx_domain_blacklist_source_id
			WHERE d.source_id = ? AND d.id > ? AND d.id <= ?
			AND NOT EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.source_id = ? AND f.entry = d.domain))`,
		linkNew: `INSERT OR IGNORE INTO domain_blacklist_sources (entry_id, source_id)
			SELECT t.id, ? FROM temp.refresh_feed f JOIN domain_blacklist t ON t.domain = f.entry
			WHERE f.source_id = ? AND f.entry > ? AND f.entry <= ?
			AND (t.source_id IS NULL OR t.source_id <> ?)`,
		promoteStale: `UPDATE domain_blacklist
			SET source_id = (SELECT MIN(x.source_id) FROM domain_blacklist_sources x WHERE x.entry_id = domain_blacklist.id AND x.source_id <> domain_blacklist.source_id)
			WHERE id IN (SELECT d.id FROM domain_blacklist d INDEXED BY idx_domain_blacklist_source_id
				WHERE d.source_id = ? AND d.id > ? AND d.id <= ?
				AND NOT EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.source_id = ? AND f.entry = d.domain)
				AND EXISTS (SELECT 1 FROM domain_blacklist_sources x WHERE x.entry_id = d.id AND x.source_id <> d.source_id))`,
		unlinkStale: `DELETE FROM domain_blacklist_sources WHERE source_id = ? AND entry_id IN (
			SELECT x.entry_id FROM domain_blacklist_sources x JOIN domain_blacklist t ON t.id = x.entry_id
			WHERE x.source_id = ? AND NOT EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.source_id = ? AND f.entry = t.domain))`,
		dropPromoted: `DELETE FROM domain_blacklist_sources WHERE EXISTS (SELECT 1 FROM domain_blacklist t
			WHERE t.id = domain_blacklist_sources.entry_id AND t.source_id = domain_blacklist_sources.source_id)`,
	},
}

// The feed's statements touch the temporary table only; they are the same for
// both lists.
const (
	feedBound = "SELECT entry FROM temp.refresh_feed WHERE source_id = ? AND entry > ? ORDER BY entry LIMIT 1 OFFSET ?"
	feedLast  = "SELECT MAX(entry) FROM temp.refresh_feed WHERE source_id = ? AND entry > ?"
	feedStore = "INSERT OR IGNORE INTO temp.refresh_feed(source_id, entry) VALUES(?, ?)"
)

// refreshCount is what one run did to one list: the feeds read and not read,
// the entries added, moved to another source and removed, the new domains
// left out at the limit, the feeds held, and whether removals waited for a
// run in which every feed of the list was read.
type refreshCount struct {
	Added           int  `json:"added"`
	Removed         int  `json:"removed"`
	Moved           int  `json:"moved,omitempty"`
	Fetched         int  `json:"fetched"`
	Failed          int  `json:"failed"`
	NotAdded        int  `json:"not_added,omitempty"`
	Held            int  `json:"held,omitempty"`
	RemovalDeferred bool `json:"removal_deferred,omitempty"`
	// failedURLs are the feeds not read, one per line, for the alert; never
	// in the audit, since a custom URL can carry a key.
	failedURLs string
}

// feedRead is one feed of a run.
type feedRead struct {
	url      string
	sourceID int64
	owned    int // entries its source held before the run
	read     int // distinct valid entries the feed listed
	held     bool
}

// heldBelow is the share of its own entries a feed must still list for its
// stale entries to go: below it the feed is held.
const heldBelow = 0.5

// syncChunk bounds the rows one write transaction adds, moves or removes.
// Measured on 500,000 names (list_sync_perf_test.go): one statement for the
// whole feed held the write lock for 1.8 s, near the 5 s a writer waits.
var syncChunk = 25_000

// refreshList syncs one list with its feeds (see the top of this file).
func refreshList(db *sql.DB, table string, urls []string) refreshCount {
	q, ok := syncLists[table]
	if !ok {
		log.Error().Str("table", table).Msg("blacklist refresh: not a list it syncs")
		return refreshCount{}
	}
	ctx := context.Background()
	// The feed's entries go to a temporary table on one connection: it holds
	// a feed of millions of names without a Go map, and the comparisons with
	// the list run in SQLite. temp_store is MEMORY (database.Open).
	conn, err := db.Conn(ctx)
	if err != nil {
		log.Error().Err(err).Msg("blacklist refresh: no connection")
		return refreshCount{}
	}
	defer conn.Close() //nolint:errcheck // returns it to the pool
	if err := resetRefreshFeed(ctx, conn); err != nil {
		log.Error().Err(err).Msg("blacklist refresh: cannot prepare the feed table")
		return refreshCount{}
	}
	defer conn.ExecContext(ctx, "DROP TABLE IF EXISTS temp.refresh_feed") //nolint:errcheck // frees the memory before the connection goes back

	var c refreshCount
	failed := func(u string) {
		c.Failed++
		c.failedURLs += u + "\n"
	}
	// 1. Every feed, read and stored, before anything is compared: a move
	//    needs to know which other feeds still list an entry.
	var reads []feedRead
	for _, u := range urls {
		data, err := fetchRefreshFeed(u)
		if err != nil {
			failed(u)
			if errors.Is(err, errRefreshRefused) {
				log.Warn().Str("url", u).Msg("blacklist refresh: refusing non-routable/invalid URL")
			} else {
				log.Warn().Err(err).Str("url", u).Msg("blacklist refresh fetch failed")
			}
			noteSourceRefresh(ctx, conn, table, u, "failed", fetchFailure(err))
			continue
		}
		fr, err := storeFeed(ctx, conn, q, table, u, data)
		if err != nil {
			// Counted as not read: its entries stay, and nothing of this list
			// is removed in this run.
			failed(u)
			log.Error().Err(err).Str("url", u).Msg("blacklist refresh: the feed could not be stored")
			continue
		}
		c.Fetched++
		reads = append(reads, fr)
	}

	// 2. What each feed dropped: moved or removed.
	c.RemovalDeferred = c.Failed > 0
	moved, removed, err := syncStale(ctx, conn, q, reads, !c.RemovalDeferred)
	c.Moved, c.Removed = moved, removed
	if err != nil {
		log.Error().Err(err).Str("table", table).Msg("blacklist refresh: the stale entries were left in place")
	}

	// 3. What each feed added, in the room the removals left.
	for _, fr := range reads {
		added, capped, err := addNew(ctx, conn, q, fr.sourceID)
		c.Added += added
		c.NotAdded += capped
		if err != nil {
			log.Error().Err(err).Str("url", fr.url).Msg("blacklist refresh: the new entries were not all added")
		}
		if err := linkListed(ctx, conn, q, fr.sourceID); err != nil {
			log.Error().Err(err).Str("url", fr.url).Msg("blacklist refresh: the entries it lists that another source added were not all recorded under it")
		}
		if fr.held {
			c.Held++
		}
		// A source left with no entry (all moved to another feed, none to
		// add) is removed: the table shows no such source, and a hidden one
		// would still be refreshed.
		database.DropSourceIfEmpty(db, table, fr.sourceID)
	}
	if c.Added > 0 || c.Removed > 0 || c.Moved > 0 {
		log.Info().Str("table", table).Int("added", c.Added).Int("removed", c.Removed).Int("moved", c.Moved).
			Int("held", c.Held).Bool("removal_deferred", c.RemovalDeferred).Msg("blacklist refresh complete")
	}
	return c
}

func resetRefreshFeed(ctx context.Context, conn *sql.Conn) error {
	for _, s := range []string{
		"DROP TABLE IF EXISTS temp.refresh_feed",
		"CREATE TEMP TABLE refresh_feed (source_id INTEGER NOT NULL, entry TEXT NOT NULL, PRIMARY KEY (source_id, entry)) WITHOUT ROWID",
		"CREATE INDEX temp.refresh_feed_entry ON refresh_feed(entry)",
	} {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// storeFeed records the feed's source (the source a manual import of the same
// URL uses), stores its entries in the temporary table, and says whether it
// is held.
func storeFeed(ctx context.Context, conn *sql.Conn, q syncList, table, url, data string) (fr feedRead, err error) {
	fr.url = url
	if err := writeTx(ctx, conn, func(c connQuerier) error {
		id, err := database.KeyedSource(c, table, database.SourceURL, url, "")
		if err != nil {
			return err
		}
		fr.sourceID = id
		return c.QueryRow(q.bySource, fr.sourceID, fr.sourceID).Scan(&fr.owned)
	}); err != nil {
		return fr, err
	}

	// The entries go to the temporary table only: the main database is not
	// locked while a large feed is parsed.
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fr, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	stmt, err := tx.PrepareContext(ctx, feedStore)
	if err != nil {
		return fr, err
	}
	defer stmt.Close() //nolint:errcheck
	for _, line := range strings.Split(data, "\n") {
		e, v := listentry.Parse(line, q.kind)
		if v != listentry.Accepted {
			continue
		}
		res, err := stmt.ExecContext(ctx, fr.sourceID, e)
		if err != nil {
			return fr, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			fr.read++
		}
	}
	if err := tx.Commit(); err != nil {
		return fr, err
	}
	fr.held = fr.read == 0 || float64(fr.read) < heldBelow*float64(fr.owned)
	return fr, nil
}

// addNew adds the entries a stored feed lists that the list lacks, a window
// of the feed's entries per transaction. The domain list is bounded by what
// dnsmasq can hold in memory (database.DomainBlacklistLimit); past it nothing
// more is added, and capped says how many were left out.
func addNew(ctx context.Context, conn *sql.Conn, q syncList, sourceID int64) (added, capped int, err error) {
	var candidates int
	if err := conn.QueryRowContext(ctx, q.candidates, sourceID).Scan(&candidates); err != nil {
		return 0, 0, err
	}
	if candidates == 0 {
		return 0, 0, nil
	}
	full := false
	err = feedWindows(ctx, conn, sourceID, func(lo, hi string) (bool, error) {
		var n int
		err := writeTx(ctx, conn, func(c connQuerier) error {
			room := -1 // no limit
			if q.kind == listentry.Domain {
				var total int
				if err := c.QueryRow(q.count).Scan(&total); err != nil {
					return err
				}
				room = max(0, database.DomainBlacklistLimit()-total)
				full = room == 0
			}
			res, err := c.Exec(q.insertNew, sourceID, sourceID, lo, hi, room)
			if err != nil {
				return err
			}
			affected, _ := res.RowsAffected()
			n = int(affected)
			return nil
		})
		added += n
		return !full, err
	})
	if q.kind == listentry.Domain && candidates > added {
		capped = candidates - added
		log.Warn().Int("not_added", capped).Int("limit", database.DomainBlacklistLimit()).
			Msg("blacklist refresh: the domain blacklist is at SPM_DNS_BLOCKLIST_MAX_DOMAINS; entries past it were not added")
	}
	return added, capped, err
}

// syncStale moves or removes, a window per transaction, the entries each
// feed read in full no longer lists, and records each feed's refresh on its
// source. remove is false when a feed of the list was not read: entries then
// only move.
func syncStale(ctx context.Context, conn *sql.Conn, q syncList, reads []feedRead, remove bool) (moved, removed int, err error) {
	for _, fr := range reads {
		status, detail := "ok", "listed "+thousands(fr.read)+" entries"
		if fr.held {
			status = "held"
			detail = fmt.Sprintf("listed %s entries, fewer than half of the %s it added: they are kept", thousands(fr.read), thousands(fr.owned))
		} else {
			// Moves first: an entry another feed lists must not be removed.
			n, err := idWindows(ctx, conn, q, fr.sourceID, q.moveStale, func(lo, hi int64) []any {
				return []any{fr.sourceID, fr.sourceID, lo, hi, fr.sourceID, fr.sourceID}
			})
			moved += n
			if err != nil {
				return moved, removed, err
			}
			// Then an entry another source lists (an import, a hand-added
			// value, a feed not read in this run) is given that source.
			n, err = idWindows(ctx, conn, q, fr.sourceID, q.promoteStale, func(lo, hi int64) []any {
				return []any{fr.sourceID, lo, hi, fr.sourceID}
			})
			moved += n
			if err != nil {
				return moved, removed, err
			}
			// The feed's source is no longer among the other sources of an
			// entry it stopped listing.
			if err := writeTx(ctx, conn, func(c connQuerier) error {
				_, err := c.Exec(q.unlinkStale, fr.sourceID, fr.sourceID, fr.sourceID)
				return err
			}); err != nil {
				return moved, removed, err
			}
			if remove {
				n, err := idWindows(ctx, conn, q, fr.sourceID, q.deleteStale, func(lo, hi int64) []any {
					return []any{fr.sourceID, lo, hi, fr.sourceID}
				})
				removed += n
				if err != nil {
					return moved, removed, err
				}
			}
		}
		if err := writeTx(ctx, conn, func(c connQuerier) error {
			_, err := c.Exec(refreshNote, time.Now().UTC().Format("2006-01-02 15:04:05"), status, detail, fr.sourceID)
			return err
		}); err != nil {
			return moved, removed, err
		}
	}
	// A moved or promoted entry may list its new source among its others.
	if err := writeTx(ctx, conn, func(c connQuerier) error {
		_, err := c.Exec(q.dropPromoted)
		return err
	}); err != nil {
		return moved, removed, err
	}
	return moved, removed, nil
}

// linkListed records the feed's source on the entries it lists that another
// source added, a window of the feed per transaction. Not bounded by the
// domain limit: it adds no entry.
func linkListed(ctx context.Context, conn *sql.Conn, q syncList, sourceID int64) error {
	return feedWindows(ctx, conn, sourceID, func(lo, hi string) (bool, error) {
		return true, writeTx(ctx, conn, func(c connQuerier) error {
			_, err := c.Exec(q.linkNew, sourceID, sourceID, lo, hi, sourceID)
			return err
		})
	})
}

// feedWindows calls fn on each range (lo, hi] of a feed's entries, of at
// most syncChunk entries, in order, until fn says to stop or the feed ends.
// The bounds are read without the write lock.
func feedWindows(ctx context.Context, conn *sql.Conn, sourceID int64, fn func(lo, hi string) (bool, error)) error {
	lo := ""
	for {
		var hi sql.NullString
		err := conn.QueryRowContext(ctx, feedBound, sourceID, lo, syncChunk-1).Scan(&hi)
		if errors.Is(err, sql.ErrNoRows) {
			err = conn.QueryRowContext(ctx, feedLast, sourceID, lo).Scan(&hi)
		}
		if err != nil {
			return err
		}
		if !hi.Valid {
			return nil
		}
		more, err := fn(lo, hi.String)
		if err != nil || !more {
			return err
		}
		lo = hi.String
	}
}

// idWindows runs query, a move or a removal, on each range (lo, hi] of a
// source's ids in the list, of at most syncChunk of its rows, one write
// transaction each, and returns the rows it changed.
func idWindows(ctx context.Context, conn *sql.Conn, q syncList, sourceID int64, query string, args func(lo, hi int64) []any) (int, error) {
	total := 0
	var lo int64
	for {
		var hi sql.NullInt64
		err := conn.QueryRowContext(ctx, q.idBound, sourceID, lo, syncChunk-1).Scan(&hi)
		if errors.Is(err, sql.ErrNoRows) {
			err = conn.QueryRowContext(ctx, q.idLast, sourceID, lo).Scan(&hi)
		}
		if err != nil {
			return total, err
		}
		if !hi.Valid {
			return total, nil
		}
		var n int
		if err := writeTx(ctx, conn, func(c connQuerier) error {
			res, err := c.Exec(query, args(lo, hi.Int64)...)
			if err != nil {
				return err
			}
			affected, _ := res.RowsAffected()
			n = int(affected)
			return nil
		}); err != nil {
			return total, err
		}
		total += n
		lo = hi.Int64
	}
}
