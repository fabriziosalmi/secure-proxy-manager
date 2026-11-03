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
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/netguard"
)

// The refresh of the blocked lists, as a sync with each feed.
//
// Every list imported from a URL (a Popular list, an address typed in the
// import form), the built-in feeds and the URLs in ip_blacklist_urls and
// domain_blacklist_urls are downloaded again. For each feed that answers:
//
//   - the entries it lists that the list lacks are added under its source
//     (the domain list stops at its limit, as before);
//   - the entries its source added that it no longer lists go: to another
//     feed read in the same run that still lists them (the entry moves to
//     that source), or out of the list.
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
// never compared with a feed: only a url source's own entries are. The
// refresh used to only add, so an entry a feed dropped stayed blocked for
// ever, and a list imported from a URL was never downloaded again.

// syncList holds the statements of one list, so no table name is built from
// input. Every write covers one window: a range of the feed's entries for an
// insert, a range of the list's ids for a move or a removal, of at most
// syncChunk rows. The windows' bounds are read first, without the write lock,
// so a transaction holds the lock for its window alone (list_sync_perf_test.go).
type syncList struct {
	table, col string
	count      string
	bySource   string
	candidates string
	// feedBound and feedLast are a feed's entry syncChunk rows after the
	// given one, and its last entry.
	feedBound, feedLast string
	insertNew           string
	// idBound and idLast are the same for a source's rows in the list.
	idBound, idLast string
	moveStale       string
	deleteStale     string
}

var syncLists = map[string]syncList{
	"ip_blacklist":     newSyncList("ip_blacklist", "ip"),
	"domain_blacklist": newSyncList("domain_blacklist", "domain"),
}

func newSyncList(table, col string) syncList {
	// table and col are the two constants above.
	notListed := "NOT EXISTS (SELECT 1 FROM " + table + " t WHERE t." + col + " = f.entry)"
	own := "NOT EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.source_id = ? AND f.entry = " + table + "." + col + ")"
	elsewhere := "EXISTS (SELECT 1 FROM temp.refresh_feed f WHERE f.entry = " + table + "." + col + " AND f.source_id <> ?)"
	// "+source_id" keeps SQLite on the id (rowid) range: on the source index
	// it sorted every row of the source by id for each window.
	window := "+source_id = ? AND id > ? AND id <= ?"
	return syncList{
		table:      table,
		col:        col,
		count:      "SELECT COUNT(*) FROM " + table,
		bySource:   "SELECT COUNT(*) FROM " + table + " WHERE source_id = ?",
		candidates: "SELECT COUNT(*) FROM temp.refresh_feed f WHERE f.source_id = ? AND " + notListed,
		feedBound:  "SELECT entry FROM temp.refresh_feed WHERE source_id = ? AND entry > ? ORDER BY entry LIMIT 1 OFFSET ?",
		feedLast:   "SELECT MAX(entry) FROM temp.refresh_feed WHERE source_id = ? AND entry > ?",
		insertNew: "INSERT OR IGNORE INTO " + table + " (" + col + ", description, source_id) " +
			"SELECT f.entry, '', ? FROM temp.refresh_feed f WHERE f.source_id = ? AND f.entry > ? AND f.entry <= ? AND " + notListed + " LIMIT ?",
		idBound: "SELECT id FROM " + table + " WHERE +source_id = ? AND id > ? ORDER BY id LIMIT 1 OFFSET ?",
		idLast:  "SELECT MAX(id) FROM " + table + " WHERE +source_id = ? AND id > ?",
		moveStale: "UPDATE " + table + " SET source_id = (SELECT MIN(f.source_id) FROM temp.refresh_feed f WHERE f.entry = " +
			table + "." + col + " AND f.source_id <> ?) WHERE " + window + " AND " + own + " AND " + elsewhere,
		deleteStale: "DELETE FROM " + table + " WHERE " + window + " AND " + own,
	}
}

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
func refreshList(db *sql.DB, table, col string, urls []string) refreshCount {
	q, ok := syncLists[table]
	if !ok || q.col != col {
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
	var reads []feedRead
	for _, u := range urls {
		data, err := fetchRefreshFeed(u)
		if err != nil {
			c.Failed++
			c.failedURLs += u + "\n"
			if errors.Is(err, errRefreshRefused) {
				log.Warn().Str("url", u).Msg("blacklist refresh: refusing non-routable/invalid URL")
			} else {
				log.Warn().Err(err).Str("url", u).Msg("blacklist refresh fetch failed")
			}
			noteSourceRefresh(ctx, conn, table, u, "failed", fetchFailure(err))
			continue
		}
		c.Fetched++
		fr, added, capped, err := readFeed(ctx, conn, q, u, data)
		if err != nil {
			// Counted as not read: its entries stay, and nothing else of this
			// list is removed in this run.
			c.Fetched--
			c.Failed++
			c.failedURLs += u + "\n"
			log.Error().Err(err).Str("url", u).Msg("blacklist refresh: the feed could not be stored")
			continue
		}
		c.Added += added
		c.NotAdded += capped
		reads = append(reads, fr)
	}

	moved, removed, err := syncStale(ctx, conn, q, reads, c.Failed == 0)
	if err != nil {
		log.Error().Err(err).Str("table", table).Msg("blacklist refresh: the stale entries were left in place")
	}
	c.Moved, c.Removed = moved, removed
	c.RemovalDeferred = c.Failed > 0
	for _, fr := range reads {
		if fr.held {
			c.Held++
		}
		if fr.owned == 0 && fr.read == 0 {
			database.DropSourceIfEmpty(db, table, fr.sourceID)
		}
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

// feedEntry is the entry a feed line names, or "" for a line that is not one:
// a comment, an address that is not one or a LAN range (the ip_blacklist is a
// destination ACL denied before local_dst is allowed, so a LAN range would cut
// every client off from LAN services), a name that is not one.
func feedEntry(col, line string) string {
	parts := strings.Fields(line)
	if len(parts) == 0 || strings.HasPrefix(parts[0], "#") {
		return ""
	}
	entry := parts[len(parts)-1]
	switch col {
	case "ip":
		if !netguard.IsValidCIDR(entry) || netguard.IsLANBogonCIDR(entry) {
			return ""
		}
	case "domain":
		if !netguard.IsValidDomainEntry(entry) {
			return ""
		}
	}
	return entry
}

// readFeed stores one feed's entries, then adds those the list lacks under the
// feed's source, the source a manual import of the same URL uses.
func readFeed(ctx context.Context, conn *sql.Conn, q syncList, url, data string) (fr feedRead, added, capped int, err error) {
	fr.url = url
	// The source first, in a short write: its id keys the feed's entries.
	if err := writeTx(ctx, conn, func(c connQuerier) error {
		id, err := database.KeyedSource(c, q.table, database.SourceURL, url, "")
		if err != nil {
			return err
		}
		fr.sourceID = id
		return c.QueryRow(q.bySource, fr.sourceID).Scan(&fr.owned)
	}); err != nil {
		return fr, 0, 0, err
	}

	// The entries, into the temporary table only: the main database is not
	// locked while a large feed is parsed.
	ttx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fr, 0, 0, err
	}
	defer ttx.Rollback() //nolint:errcheck
	stmt, err := ttx.PrepareContext(ctx, "INSERT OR IGNORE INTO temp.refresh_feed(source_id, entry) VALUES(?, ?)")
	if err != nil {
		return fr, 0, 0, err
	}
	for _, line := range strings.Split(data, "\n") {
		if e := feedEntry(q.col, line); e != "" {
			if res, err := stmt.ExecContext(ctx, fr.sourceID, e); err != nil {
				stmt.Close()
				return fr, 0, 0, err
			} else if n, _ := res.RowsAffected(); n > 0 {
				fr.read++
			}
		}
	}
	stmt.Close()
	if err := ttx.Commit(); err != nil {
		return fr, 0, 0, err
	}
	fr.held = fr.read == 0 || float64(fr.read) < heldBelow*float64(fr.owned)

	// The new entries, syncChunk at a time: the list is locked for one insert
	// at a time. The domain list is bounded by what dnsmasq can hold in memory
	// (database.DomainBlacklistLimit); past it nothing more is added, and the
	// count says so.
	var candidates int
	if err := conn.QueryRowContext(ctx, q.candidates, fr.sourceID).Scan(&candidates); err != nil {
		return fr, 0, 0, err
	}
	full := false
	err = feedWindows(ctx, conn, q, fr.sourceID, func(lo, hi string) (bool, error) {
		var n int
		err := writeTx(ctx, conn, func(c connQuerier) error {
			room := -1 // no limit
			if q.col == "domain" {
				var total int
				if err := c.QueryRow(q.count).Scan(&total); err != nil {
					return err
				}
				room = max(0, database.DomainBlacklistLimit()-total)
				full = room == 0
			}
			res, err := c.Exec(q.insertNew, fr.sourceID, fr.sourceID, lo, hi, room)
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
	if err != nil {
		return fr, added, 0, err
	}
	if q.col == "domain" && candidates > added {
		capped = candidates - added
		log.Warn().Int("not_added", capped).Int("limit", database.DomainBlacklistLimit()).
			Msg("blacklist refresh: the domain blacklist is at SPM_DNS_BLOCKLIST_MAX_DOMAINS; entries past it were not added")
	}
	return fr, added, capped, nil
}

// syncStale moves or removes, a window per transaction, the entries each
// feed read in full no longer lists, and records each feed's refresh on its
// source.
// remove is false when a feed of the list was not read: entries then only
// move.
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
	return moved, removed, nil
}

// feedWindows calls fn on each range (lo, hi] of a feed's entries, of at
// most syncChunk entries, in order, until fn says to stop or the feed ends.
// The bounds are read without the write lock.
func feedWindows(ctx context.Context, conn *sql.Conn, q syncList, sourceID int64, fn func(lo, hi string) (bool, error)) error {
	lo := ""
	for {
		var hi sql.NullString
		err := conn.QueryRowContext(ctx, q.feedBound, sourceID, lo, syncChunk-1).Scan(&hi)
		if errors.Is(err, sql.ErrNoRows) {
			err = conn.QueryRowContext(ctx, q.feedLast, sourceID, lo).Scan(&hi)
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
// source's ids in the list, of at most syncChunk rows, one write
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

const refreshNote = "UPDATE list_sources SET refreshed_at = ?, refresh_status = ?, refresh_detail = ? WHERE id = ?"

// connQuerier is a connection as database.KeyedSource takes it.
type connQuerier struct {
	ctx  context.Context
	conn *sql.Conn
}

func (c connQuerier) Exec(query string, args ...any) (sql.Result, error) {
	return c.conn.ExecContext(c.ctx, query, args...)
}

func (c connQuerier) QueryRow(query string, args ...any) *sql.Row {
	return c.conn.QueryRowContext(c.ctx, query, args...)
}

// writeTx runs fn in a transaction that takes the write lock first (BEGIN
// IMMEDIATE). A transaction that reads, then writes, after another connection
// wrote in between, fails in WAL mode with SQLITE_BUSY_SNAPSHOT, which the
// busy timeout does not wait out: the log tailer writes every few seconds, so
// the refresh would fail at random. Taken first, the lock is waited for.
func writeTx(ctx context.Context, conn *sql.Conn, fn func(q connQuerier) error) error {
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	held := time.Now()
	if err := fn(connQuerier{ctx, conn}); err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return err
	}
	d := time.Since(held)
	writeLockHeld(d)
	// The next transaction waits as long as this one held the lock (up to
	// 100 ms): back to back, they starved the log tailer, whose busy handler
	// retries every up to 100 ms and kept missing the gap between a COMMIT
	// and the next BEGIN (measured: 82 ms held at most, 1.5 s waited).
	time.Sleep(min(d, 100*time.Millisecond))
	return nil
}

// writeLockHeld sees how long each write transaction held the lock; the
// performance test measures with it.
var writeLockHeld = func(time.Duration) {}

// noteSourceRefresh records a feed that could not be read on its source, if
// it has one; a built-in feed never imported has none, and none is created.
func noteSourceRefresh(ctx context.Context, conn *sql.Conn, table, url, status, detail string) {
	_, _ = conn.ExecContext(ctx,
		"UPDATE list_sources SET refreshed_at = ?, refresh_status = ?, refresh_detail = ? WHERE list = ? AND kind = 'url' AND source = ?",
		time.Now().UTC().Format("2006-01-02 15:04:05"), status, detail, table, url)
}

// fetchFailure says why a feed was not read without its URL, which the source
// row already holds.
func fetchFailure(err error) string {
	switch {
	case errors.Is(err, errRefreshRefused):
		return "not downloaded: the address is not a public one"
	case strings.HasPrefix(err.Error(), "HTTP "):
		return "not downloaded: the server answered " + err.Error()
	default:
		return "not downloaded: no answer"
	}
}

// thousands writes n with a comma between thousands, as the UI writes counts
// (50,772): the note is shown as it is stored.
func thousands(n int) string {
	s := fmt.Sprint(n)
	if n < 0 {
		return "-" + thousands(-n)
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
