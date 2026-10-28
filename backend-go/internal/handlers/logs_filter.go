package handlers

import (
	"database/sql"
	"errors"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// logFilter is what GET /api/logs and GET /api/logs/export select rows by.
// Every value is bound as a query argument; the SQL text holds only
// constants and placeholders.
//
//   - source_ip: one source address (exact) or a network CIDR (/24, /64).
//     With gdpr_mode on, only a network CIDR is accepted.
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
	sourceCIDR      bool
	sourceIPs       []string
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

// parseNetworkCIDR parses and normalizes a network CIDR (e.g. 192.168.1.0/24 or 2001:db8::/64).
func parseNetworkCIDR(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, err
	}
	addr := p.Addr().WithZone("")
	bits := p.Bits()
	if addr.Is4In6() {
		addr = addr.Unmap()
		if bits >= 96 {
			bits -= 96
		} else {
			bits = 24
		}
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

// matchNetworkIPs returns all distinct source_ip strings stored in proxy_logs
// whose parsed address falls inside prefix.
func matchNetworkIPs(db *sql.DB, prefix netip.Prefix) ([]string, error) {
	rows, err := db.Query("SELECT DISTINCT source_ip FROM proxy_logs WHERE source_ip IS NOT NULL AND source_ip != ''")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var matched []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		addr = addr.WithZone("").Unmap()
		if prefix.Contains(addr) {
			matched = append(matched, s)
		}
	}
	sort.Strings(matched)
	return matched, rows.Err()
}

// resolveSource validates f.sourceIP against gdpr_mode and expands a network
// CIDR into the matching source_ip values in db.
func (f logFilter) resolveSource(db *sql.DB, gdpr bool) (logFilter, error) {
	if f.sourceIP == "" {
		return f, nil
	}
	if strings.Contains(f.sourceIP, "/") {
		prefix, err := parseNetworkCIDR(f.sourceIP)
		if err != nil {
			return f, errors.New("source_ip must be a valid IP address or network CIDR")
		}
		ips, err := matchNetworkIPs(db, prefix)
		if err != nil {
			return f, errors.New("failed to resolve network filter")
		}
		f.sourceCIDR = true
		f.sourceIPs = ips
		return f, nil
	}
	if gdpr {
		return f, errors.New("GDPR mode is enabled: filter source_ip by network CIDR (for example 192.168.1.0/24 or 2001:db8:1:2::/64) instead of a single IP address")
	}
	return f, nil
}

// hidesInternal reports whether the filter leaves internal sources out.
func (f logFilter) hidesInternal() bool {
	return !f.includeInternal && f.sourceIP == ""
}

// conds are the filter's conditions other than the internal-source one and
// the cursor, with their arguments.
func (f logFilter) conds() ([]database.SQLText, []any) {
	var c []database.SQLText
	var a []any
	if f.sourceCIDR {
		if len(f.sourceIPs) == 0 {
			c = append(c, "0 = 1")
		} else {
			c = append(c, "source_ip IN ("+placeholders(len(f.sourceIPs))+")")
			a = append(a, toArgs(f.sourceIPs)...)
		}
	} else if f.sourceIP != "" {
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
func (f logFilter) where(internal []string, page bool) (database.SQLText, []any) {
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
	return database.JoinSQL(c, " AND "), a
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
		if err := tx.QueryRow(string(t.query), t.args...).Scan(&v); err != nil {
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
	query    database.SQLText
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
	term := func(sign int, isInternal bool, extra []database.SQLText, extraArgs []any) countTerm {
		c := append(append([]database.SQLText{}, base...), extra...)
		var w database.SQLText = "1 = 1"
		if len(c) > 0 {
			w = database.JoinSQL(c, " AND ")
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
	with := func(isInternal bool, extra []database.SQLText, extraArgs []any) {
		terms = append(terms, term(1, isInternal, extra, extraArgs))
		if allowed {
			terms = append(terms, term(-1, isInternal, append([]database.SQLText{"blocked = 1"}, extra...), extraArgs))
		}
	}
	const everyRow, internalRows = false, true
	with(everyRow, nil, nil)
	if f.hidesInternal() && len(internal) > 0 {
		in, inArgs := onlyInternal(internal)
		with(internalRows, []database.SQLText{in}, inArgs)
	}
	return terms
}

// escapeLike makes s match itself in a LIKE pattern with ESCAPE '\'.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
