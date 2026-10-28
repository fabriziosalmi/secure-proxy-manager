package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"
)

// The database is checked twice, by two checks of different cost.
//
// Before serving, Init runs PRAGMA quick_check: every page, the b-tree
// structure, the free list and the NOT NULL and CHECK constraints. It is
// fatal, as the full check used to be, so a database whose pages are
// damaged still stops the start.
//
// PRAGMA integrity_check also verifies that every index holds exactly the
// rows of its table, one seek per row and index: on 1,000,000 proxy_logs
// rows with nine indexes that took 57 to 77 s at the compose limit of 0.25
// CPU, against 4 s for quick_check, and it ran with the pool's 50 MB page
// cache, 111 MiB of anonymous memory in a 128 MiB container. It now runs
// after start-up on a connection of its own (IntegrityCheck) with a 2 MB
// cache, and a failure takes the backend out of readiness (IntegrityFailure).

// maxReported is how many lines of a failed check are kept in the error.
const maxReported = 10

// checkLines runs a check pragma and returns nil when its only line is "ok",
// otherwise an error carrying the first maxReported lines it returned.
func checkLines(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, pragma SQLText) error {
	rows, err := q.QueryContext(ctx, string("PRAGMA "+pragma))
	if err != nil {
		return fmt.Errorf("%s: %w", pragma, err)
	}
	defer rows.Close()
	var lines []string
	n := 0
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return fmt.Errorf("%s: %w", pragma, err)
		}
		n++
		if len(lines) < maxReported {
			lines = append(lines, line)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%s: %w", pragma, err)
	}
	if n == 1 && lines[0] == "ok" {
		return nil
	}
	if n == 0 {
		return fmt.Errorf("%s returned nothing", pragma)
	}
	return fmt.Errorf("%s returned %d line(s): %s", pragma, n, strings.Join(lines, "; "))
}

// QuickCheck runs PRAGMA quick_check on db.
func QuickCheck(ctx context.Context, db *sql.DB) error {
	return checkLines(ctx, db, "quick_check")
}

// integrityCacheKiB is the page cache of the connection IntegrityCheck opens.
// The check reads every page once per index, so a larger cache buys nothing:
// measured on the 440 MiB fixture, 9.7 s with 2 MB and 11.9 s with 50 MB.
const integrityCacheKiB = 2000

// IntegrityCheck runs the full PRAGMA integrity_check on the database at path,
// on a read-only connection of its own with a small page cache, so it neither
// holds one of the pool's connections for the minute it takes nor fills a
// large cache. It reads a snapshot: writers carry on while it runs.
func IntegrityCheck(ctx context.Context, path string) error {
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(5000)&_pragma=cache_size(-%d)", path, integrityCacheKiB)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("integrity_check: open: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	return checkLines(ctx, db, "integrity_check")
}

// integrityFailure holds the failure of the last full check, if any.
var integrityFailure atomic.Pointer[string]

// RecordIntegrity stores the outcome of a full check: a failure is kept, and
// readiness reports it, until a later check passes. The caller does not
// record a check that shutdown cut short: that is not an outcome.
func RecordIntegrity(err error) {
	if err == nil {
		integrityFailure.Store(nil)
		return
	}
	msg := err.Error()
	integrityFailure.Store(&msg)
}

// IntegrityFailure is the failure of the last full check, or "" when the last
// check passed or none has run yet.
func IntegrityFailure() string {
	if p := integrityFailure.Load(); p != nil {
		return *p
	}
	return ""
}
