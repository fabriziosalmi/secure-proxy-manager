package workers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The write transactions of the list sync (list_sync.go) and the words its
// notes are written in.

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
	if n < 0 {
		return "-" + thousands(-n)
	}
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
