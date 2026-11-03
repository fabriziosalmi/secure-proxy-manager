package database

import (
	"database/sql"
	"strconv"
	"time"
)

// WAFSignal is one signal the WAF sent: a category that describes what a
// client did on the way out (a typosquatted name, regular check-ins, a
// secret in a body), at one instant. Most score below the block threshold,
// so no block event carries them; a day of one client's signals is what the
// trajectory correlator reads.
type WAFSignal struct {
	At       time.Time
	ClientIP string
	Host     string
	Category string
	Rule     string
	Observed bool // matched in Log only: scored 0
	Blocked  bool // the request it came with was blocked
	EventID  string
}

// StoreWAFSignals inserts sigs in one transaction. A signal already stored
// (same event and category) is left as it is: the WAF retries a report whose
// answer it did not get, which the backend may have stored.
func StoreWAFSignals(db *sql.DB, sigs []WAFSignal) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO waf_signals
		(ts_ms, client_ip, host, category, rule, observed, blocked, event_id) VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, s := range sigs {
		if _, err := stmt.Exec(s.At.UnixMilli(), capText(s.ClientIP), capText(s.Host), capText(s.Category),
			capText(s.Rule), s.Observed, s.Blocked, capText(s.EventID)); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ClearWAFRecords deletes what the WAF reported, blocks and signals, and
// the trajectories read from them, with the access log they go with.
func ClearWAFRecords(db *sql.DB) {
	db.Exec("DELETE FROM waf_events")       //nolint:errcheck
	db.Exec("DELETE FROM waf_signals")      //nolint:errcheck
	db.Exec("DELETE FROM waf_trajectories") //nolint:errcheck
}

// PruneWAFRecords deletes what the WAF reported more than days ago, and the
// trajectories that started then.
func PruneWAFRecords(db *sql.DB, days int) error {
	if _, err := db.Exec("DELETE FROM waf_events WHERE timestamp < datetime('now', ?)", "-"+strconv.Itoa(days)+" days"); err != nil { // slopless-disable-line VBC-004 -- the concatenation builds a bound argument, not the statement
		return err
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()
	if _, err := db.Exec("DELETE FROM waf_signals WHERE ts_ms < ?", cutoff); err != nil {
		return err
	}
	_, err := db.Exec("DELETE FROM waf_trajectories WHERE start_ms < ?", cutoff)
	return err
}
