package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// logFilter is what GET /api/logs and GET /api/logs/export select rows by.
// Every value is bound as a query argument; the SQL text holds only
// constants and placeholders.
//
//   - source_ip: one source address, exact.
//   - outcome: "allowed" or "blocked", from the blocked flag.
//   - reason: the rule that blocked the request (a block_reason key, as in
//     docs/design/block-reasons.md). It selects blocked rows only.
//   - q: a substring of the destination, case-insensitive for ASCII as
//     SQLite LIKE is; % and _ in it are matched literally.
//   - include_internal: the stack's own traffic (sources.Classifier) is left
//     out unless this is true. A source_ip names the address wanted, so it is
//     never left out for being internal.
//   - before_id: a cursor; only rows with a lower id, for "Load older".
type logFilter struct {
	sourceIP        string
	outcome         string
	reason          string
	q               string
	includeInternal bool
	beforeID        int64
}

// Bounds on the filter values: the longest IPv6 text is 45 bytes, a reason
// key is a short identifier, and a destination search past a few hundred
// bytes is not a search.
const (
	maxSourceIPLen = 64
	maxQueryLen    = 256
)

var reasonKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func parseLogFilter(r *http.Request) (logFilter, error) {
	v := r.URL.Query()
	f := logFilter{
		sourceIP: strings.TrimSpace(v.Get("source_ip")),
		outcome:  v.Get("outcome"),
		reason:   v.Get("reason"),
		q:        strings.TrimSpace(v.Get("q")),
	}
	if len(f.sourceIP) > maxSourceIPLen {
		return f, errors.New("source_ip is too long")
	}
	switch f.outcome {
	case "", "all":
		f.outcome = ""
	case "allowed", "blocked":
	default:
		return f, errors.New("outcome must be allowed or blocked")
	}
	if f.reason != "" && !reasonKeyRE.MatchString(f.reason) {
		return f, errors.New("reason must be a block reason key")
	}
	if len(f.q) > maxQueryLen {
		return f, errors.New("q is too long")
	}
	switch s := v.Get("include_internal"); s {
	case "", "false", "0":
	case "true", "1":
		f.includeInternal = true
	default:
		return f, errors.New("include_internal must be true or false")
	}
	if s := v.Get("before_id"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 1 {
			return f, errors.New("before_id must be a positive row id")
		}
		f.beforeID = n
	}
	return f, nil
}

// hidesInternal reports whether the filter leaves internal sources out.
func (f logFilter) hidesInternal() bool {
	return !f.includeInternal && f.sourceIP == ""
}

// conds are the filter's conditions other than the internal-source one and
// the cursor, with their arguments.
func (f logFilter) conds() ([]string, []any) {
	var c []string
	var a []any
	if f.sourceIP != "" {
		c, a = append(c, "source_ip = ?"), append(a, f.sourceIP)
	}
	switch f.outcome {
	case "blocked":
		c = append(c, "blocked = 1")
	case "allowed":
		// != 1 rather than = 0: the complement of blocked = 1 exactly, which
		// countLogs relies on (blocked is NOT NULL).
		c = append(c, "blocked != 1")
	}
	if f.reason != "" {
		// blocked = 1 is what lets idx_proxy_logs_blocked_reason (a partial
		// index on blocked rows) serve this condition.
		c, a = append(c, "blocked = 1 AND block_reason = ?"), append(a, f.reason)
	}
	if f.q != "" {
		c, a = append(c, `destination LIKE ? ESCAPE '\'`), append(a, "%"+escapeLike(f.q)+"%")
	}
	return c, a
}

// where is the condition selecting the filter's rows. internal is the list
// of internal sources present in the log (InternalSources.Present). The
// cursor applies only with page set: a count covers every matching row.
func (f logFilter) where(internal []string, page bool) (string, []any) {
	c, a := f.conds()
	if f.hidesInternal() {
		ext, extArgs := notInternal(internal)
		c, a = append(c, ext), append(a, extArgs...)
	}
	if page && f.beforeID > 0 {
		c, a = append(c, "id < ?"), append(a, f.beforeID)
	}
	if len(c) == 0 {
		return "1 = 1", nil
	}
	return strings.Join(c, " AND "), a
}

// countLogs counts the rows f matches and, when f leaves internal sources
// out, the rows it leaves out for that alone (hidden is nil otherwise).
//
// The two conditions that no index can count, "not one of the internal
// sources" and "not blocked", are counted as differences instead: every
// matching row minus the internal ones (a range of idx_proxy_logs_source_ip),
// every row minus the blocked ones (a partial index). Counted directly, each
// read the whole table: about 120 and 220 ms on 1M rows against about 15
// (docs/api/logs.md). The counts run in one read transaction, so a row the
// tailer inserts meanwhile cannot land in one count and not the other.
func countLogs(db *sql.DB, f logFilter, internal []string) (total int, hidden *int, err error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback() //nolint:errcheck // read only

	var h int
	for _, t := range f.countTerms(internal) {
		var v int
		if err := tx.QueryRow(t.query, t.args...).Scan(&v); err != nil {
			return 0, nil, err
		}
		v *= t.sign
		if t.internal {
			h += v
		} else {
			total += v
		}
	}
	// The internal terms counted rows the filter leaves out: they come off
	// the total, which the first terms counted with them.
	total -= h
	if f.hidesInternal() {
		hidden = &h
	}
	return total, hidden, nil
}

// countTerm is one COUNT query of countLogs, added (sign 1) or subtracted
// (sign -1). internal marks the terms that count the internal sources' rows.
type countTerm struct {
	query    string
	args     []any
	sign     int
	internal bool
}

func (f logFilter) countTerms(internal []string) []countTerm {
	allowed := f.outcome == "allowed"
	g := f
	if allowed {
		g.outcome = ""
	}
	base, baseArgs := g.conds()
	term := func(sign int, isInternal bool, extra []string, extraArgs []any) countTerm {
		c := append(append([]string{}, base...), extra...)
		w := "1 = 1"
		if len(c) > 0 {
			w = strings.Join(c, " AND ")
		}
		return countTerm{
			// The conditions are constants with placeholders; every value is bound.
			query:    "SELECT COUNT(*) FROM proxy_logs WHERE " + w,
			args:     append(append([]any{}, baseArgs...), extraArgs...),
			sign:     sign,
			internal: isInternal,
		}
	}
	// with adds the rows meeting extra, less the blocked ones among them when
	// the filter asks for allowed rows.
	var terms []countTerm
	with := func(isInternal bool, extra []string, extraArgs []any) {
		terms = append(terms, term(1, isInternal, extra, extraArgs))
		if allowed {
			terms = append(terms, term(-1, isInternal, append([]string{"blocked = 1"}, extra...), extraArgs))
		}
	}
	const everyRow, internalRows = false, true
	with(everyRow, nil, nil)
	if f.hidesInternal() && len(internal) > 0 {
		in, inArgs := onlyInternal(internal)
		with(internalRows, []string{in}, inArgs)
	}
	return terms
}

// escapeLike makes s match itself in a LIKE pattern with ESCAPE '\'.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
