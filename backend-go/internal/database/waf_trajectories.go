package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// WAFTrajectory is one client's trajectory as the correlator found it: the
// rule that held, when it held (Closed), and its window of signals from
// Start to End, named once each.
type WAFTrajectory struct {
	ID         int64     `json:"id"`
	ClientIP   string    `json:"client_ip"`
	Rule       string    `json:"rule"`
	Start      time.Time `json:"start"`
	Closed     time.Time `json:"closed"`
	End        time.Time `json:"end"`
	Phases     []string  `json:"phases"`
	Categories []string  `json:"categories"`
	Hosts      []string  `json:"hosts"`
	Signals    int       `json:"signals"`
}

// trajectoryMaxHosts bounds the hosts a row names; a burst to many hosts is
// one action, and the signals in the window name them all.
const trajectoryMaxHosts = 50

func jsonList(v []string, max int) string {
	if len(v) > max {
		v = v[:max]
	}
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// InsertWAFTrajectory stores t unless the client already has a trajectory
// starting at the same instant; inserted says which.
func InsertWAFTrajectory(db *sql.DB, t WAFTrajectory) (id int64, inserted bool, err error) {
	res, err := db.Exec(`INSERT OR IGNORE INTO waf_trajectories
		(client_ip, rule, start_ms, closed_ms, end_ms, phases, categories, hosts, signals) VALUES (?,?,?,?,?,?,?,?,?)`,
		capText(t.ClientIP), t.Rule, t.Start.UnixMilli(), t.Closed.UnixMilli(), t.End.UnixMilli(),
		jsonList(t.Phases, 3), jsonList(t.Categories, wafEventMaxList), jsonList(t.Hosts, trajectoryMaxHosts), t.Signals)
	if err != nil {
		return 0, false, err
	}
	n, _ := res.RowsAffected()
	id, _ = res.LastInsertId()
	return id, n == 1, nil
}

// UpdateWAFTrajectory rewrites the window of trajectory id (its end and what
// it holds) while signals still arrive within it.
func UpdateWAFTrajectory(db *sql.DB, id int64, t WAFTrajectory) error {
	_, err := db.Exec(`UPDATE waf_trajectories SET end_ms = ?, phases = ?, categories = ?, hosts = ?, signals = ? WHERE id = ?`,
		t.End.UnixMilli(), jsonList(t.Phases, 3), jsonList(t.Categories, wafEventMaxList), jsonList(t.Hosts, trajectoryMaxHosts), t.Signals, id)
	return err
}

// scanTrajectory reads the columns every trajectory query selects, in this
// order: id, client_ip, rule, start_ms, closed_ms, end_ms, phases,
// categories, hosts, signals.
func scanTrajectory(row interface{ Scan(...any) error }) (WAFTrajectory, error) {
	var t WAFTrajectory
	var start, closed, end int64
	var phases, cats, hosts string
	if err := row.Scan(&t.ID, &t.ClientIP, &t.Rule, &start, &closed, &end, &phases, &cats, &hosts, &t.Signals); err != nil {
		return t, err
	}
	t.Start, t.Closed, t.End = time.UnixMilli(start).UTC(), time.UnixMilli(closed).UTC(), time.UnixMilli(end).UTC()
	_ = json.Unmarshal([]byte(phases), &t.Phases)
	_ = json.Unmarshal([]byte(cats), &t.Categories)
	_ = json.Unmarshal([]byte(hosts), &t.Hosts)
	return t, nil
}

// LastWAFTrajectory is the client's latest trajectory by start; ok is false
// when it has none.
func LastWAFTrajectory(db *sql.DB, client string) (t WAFTrajectory, ok bool, err error) {
	t, err = scanTrajectory(db.QueryRow(`SELECT id, client_ip, rule, start_ms, closed_ms, end_ms, phases, categories, hosts, signals FROM waf_trajectories
		WHERE client_ip = ? ORDER BY start_ms DESC LIMIT 1`, client))
	if errors.Is(err, sql.ErrNoRows) {
		return t, false, nil
	}
	return t, err == nil, err
}

// GetWAFTrajectory is trajectory id; ok is false when there is none.
func GetWAFTrajectory(db *sql.DB, id int64) (t WAFTrajectory, ok bool, err error) {
	t, err = scanTrajectory(db.QueryRow(`SELECT id, client_ip, rule, start_ms, closed_ms, end_ms, phases, categories, hosts, signals FROM waf_trajectories WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return t, false, nil
	}
	return t, err == nil, err
}

// ListWAFTrajectories is the trajectories that closed at or after since,
// latest first, at most limit.
func ListWAFTrajectories(db *sql.DB, since time.Time, limit int) ([]WAFTrajectory, error) {
	rows, err := db.Query(`SELECT id, client_ip, rule, start_ms, closed_ms, end_ms, phases, categories, hosts, signals FROM waf_trajectories
		WHERE closed_ms >= ? ORDER BY closed_ms DESC, id DESC LIMIT ?`, since.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WAFTrajectory{}
	for rows.Next() {
		t, err := scanTrajectory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SignalClientsSince names the clients with a signal at or after since.
func SignalClientsSince(db *sql.DB, since time.Time) ([]string, error) {
	rows, err := db.Query(`SELECT DISTINCT client_ip FROM waf_signals WHERE ts_ms >= ? ORDER BY client_ip`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClientSignals is client's signals from from to until (both inclusive), in
// the order they came.
func ClientSignals(db *sql.DB, client string, from, until time.Time) ([]WAFSignal, error) {
	rows, err := db.Query(`SELECT ts_ms, host, category, rule, observed, blocked, event_id FROM waf_signals
		WHERE client_ip = ? AND ts_ms >= ? AND ts_ms <= ? ORDER BY ts_ms, id`, client, from.UnixMilli(), until.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WAFSignal
	for rows.Next() {
		s := WAFSignal{ClientIP: client}
		var ts int64
		if err := rows.Scan(&ts, &s.Host, &s.Category, &s.Rule, &s.Observed, &s.Blocked, &s.EventID); err != nil {
			return nil, err
		}
		s.At = time.UnixMilli(ts).UTC()
		out = append(out, s)
	}
	return out, rows.Err()
}
