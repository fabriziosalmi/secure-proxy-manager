package handlers

import (
	"database/sql"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"net/http"
	"strconv"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/privacy"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
	"github.com/go-chi/chi/v5"
)

type LogHandlers struct {
	db *sql.DB
	// src finds the internal sources the timeline leaves out, as the
	// dashboard's counts do.
	src *InternalSources
}

func NewLogHandlers(db *sql.DB) *LogHandlers {
	return &LogHandlers{db: db, src: NewInternalSources(db, nil)}
}

// WithSources attaches the internal-source finder the deployment uses.
func (h *LogHandlers) WithSources(s *InternalSources) *LogHandlers {
	h.src = s
	return h
}

func (h *LogHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/logs", h.GetLogs)
	r.With(authMW).Get("/api/logs/export", h.Export)
	r.With(authMW).Get("/api/logs/stats", h.Stats)
	r.With(authMW).Get("/api/logs/timeline", h.Timeline)
	r.With(authMW).Post("/api/logs/clear", h.Clear)
	r.With(authMW).Post("/api/logs/clear-old", h.ClearOld)
}

func (h *LogHandlers) gdprEnabled() bool {
	return privacy.Enabled(h.db)
}

// GetLogs lists access-log rows matching the filters (logFilter), newest
// first by default. meta.total counts the rows the filters match; when
// internal sources are left out, meta.internal counts the rows that were left
// out for that reason alone, so the page can say what it hides.
func (h *LogHandlers) GetLogs(w http.ResponseWriter, r *http.Request) {
	f, err := parseLogFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	gdpr := h.gdprEnabled()
	f, err = f.resolveSource(h.db, gdpr)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit := clamp(queryInt(r, "limit", 25), 1, 500)
	offset := max0(queryInt(r, "offset", 0))
	sort := sanitiseSort(r.URL.Query().Get("sort"), []database.SQLText{"timestamp", "source_ip", "destination", "status", "bytes", "method", "id"}, "timestamp")
	order := sanitiseOrder(r.URL.Query().Get("order"))
	if f.beforeID > 0 {
		// A cursor is a position in id order: the page after it is the next
		// lower ids, whatever sort was asked for.
		sort, order, offset = "id", "DESC", 0
	}
	internal := h.src.Present()

	total, hidden, err := countLogs(h.db, f, internal)
	if err != nil {
		writeInternalError(w, "logs_count", err)
		return
	}
	meta := ListMeta{Total: total, Limit: limit, Offset: offset, Internal: hidden}

	pageWhere, pageArgs := f.where(internal, true)
	// sort and order are sanitised against whitelists (sanitiseSort/sanitiseOrder) — safe for interpolation.
	// The conditions are constants with placeholders; every value is bound.
	// #nosec G202
	// #nosec G701
	rows, err := h.db.Query(
		string("SELECT "+logColumns+" FROM proxy_logs WHERE "+pageWhere+" ORDER BY "+sort+" "+order+" LIMIT ? OFFSET ?"), // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
		append(pageArgs, limit, offset)...,
	)
	if err != nil {
		writeInternalError(w, "list_logs", err)
		return
	}
	defer rows.Close()

	logs := []map[string]any{}
	for rows.Next() {
		row, err := scanLogRow(rows)
		if err != nil {
			writeInternalError(w, "scan_logs", err)
			return
		}
		logs = append(logs, row.wire(h.src, gdpr))
	}
	if err := rows.Err(); err != nil {
		writeInternalError(w, "list_logs", err)
		return
	}
	writeList(w, logs, meta)
}

// logColumns are the proxy_logs columns a log row is read from, in the order
// scanLogRow expects.
const logColumns = "id,timestamp,source_ip,method,destination,status,bytes,blocked,block_reason,resolved_ip,event_id"

type logRow struct {
	id                                      int64
	ts, srcIP, method, dest, status, reason sql.NullString
	bytes, blocked                          sql.NullInt64
	resolvedIP, eventID                     sql.NullString
}

func scanLogRow(rows *sql.Rows) (logRow, error) {
	var l logRow
	err := rows.Scan(&l.id, &l.ts, &l.srcIP, &l.method, &l.dest, &l.status, &l.bytes, &l.blocked, &l.reason, &l.resolvedIP, &l.eventID)
	return l, err
}

// wire is the row as GET /api/logs returns it. The source is classified on
// the stored address, before GDPR mode masks it.
func (l logRow) wire(src *InternalSources, gdpr bool) map[string]any {
	ip := l.srcIP.String
	internal, kind := src.Classify(ip)
	if gdpr {
		ip = maskIP(ip)
	}
	return map[string]any{
		"id":        l.id,
		"timestamp": l.ts.String,
		// source_ip on the wire as well as in the schema: the address used
		// to be client_ip here, source_ip in the dashboard payload and
		// ip_address in the clients endpoint: three names for one concept
		// in one API consumed by one UI (SECURE-DOM-08).
		"source_ip":   ip,
		"method":      l.method.String,
		"destination": l.dest.String,
		"status":      l.status.String,
		"bytes":       l.bytes.Int64,
		// The rule that blocked the request (workers/block_reason.go):
		// "none" when it was not blocked, "unclassified" for a row logged
		// before reasons were recorded.
		"blocked":      l.blocked.Int64 == 1,
		"reason":       l.reason.String,
		"reason_label": workers.ReasonLabel(l.reason.String),
		// The stack's own traffic (sources.Classifier) and what the address
		// is, where that is known; kind is empty otherwise.
		"internal": internal,
		"kind":     kind,
		// The upstream address the proxy connected to, null when it reached
		// no server (a denied request) or for a row logged before it was
		// recorded. A server's address, not a client's: GDPR mode keeps it.
		"resolved_ip": nullString(l.resolvedIP),
		// The WAF's event ID on a WAF block (X-WAF-Event-Id), null otherwise:
		// GET /api/waf/events/{event_id} has the rules behind it. The tailer
		// stores "" for a row without one.
		"event_id": nullIfEmpty(l.eventID),
	}
}

func (h *LogHandlers) Stats(w http.ResponseWriter, r *http.Request) {
	var total, blocked, ipBlocks int
	var lastImport sql.NullString
	// Client requests only, like every other statistic (clientRows).
	h.db.QueryRow(string("SELECT COUNT(*) FROM proxy_logs WHERE " + clientRows)).Scan(&total)                   //nolint:errcheck  // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
	h.db.QueryRow(string("SELECT COUNT(*) FROM proxy_logs WHERE blocked = 1 AND " + clientRows)).Scan(&blocked) //nolint:errcheck  // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
	// Direct-IP blocks are the rows whose reason says so. A row logged before
	// reasons were recorded keeps the count it always had, the URL heuristic,
	// rather than being reassigned.
	// slopless-disable-next-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
	h.db.QueryRow(string("SELECT COUNT(*) FROM proxy_logs WHERE blocked = 1 AND " + clientRows + ` AND (block_reason = 'direct_ip'
		OR (block_reason = 'unclassified' AND (destination LIKE 'http://%.%.%.%' OR destination LIKE 'https://%.%.%.%')))`)).Scan(&ipBlocks) //nolint:errcheck
	h.db.QueryRow("SELECT MAX(timestamp) FROM proxy_logs").Scan(&lastImport) //nolint:errcheck
	writeOK(w, map[string]any{
		"total_count":       total,
		"blocked_count":     blocked,
		"ip_blocks_count":   ipBlocks,
		"blocked_by_reason": blockedByReason(h.db, "1 = 1"),
		"last_import":       lastImport.String,
	})
}

// Timeline counts the client requests of the last ?hours= hours (24 by
// default) per hour of the zone ?tz= (an IANA name, UTC by default). time is
// the hour as the zone's clock reads it, start the epoch second it begins.
// Grouping by UTC hour put every hour at half past in a zone such as
// Asia/Kolkata (UTC+05:30): the chart read 12:30, 15:30. Rows are counted
// per quarter hour in SQL, every zone's offset being a whole number of
// quarters, and each quarter goes to the hour of the zone it starts in.
func (h *LogHandlers) Timeline(w http.ResponseWriter, r *http.Request) {
	hours := queryInt(r, "hours", 24)
	if hours < 1 || hours > 720 {
		hours = 24
	}
	loc, ok := viewerZone(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "tz must be an IANA time zone name such as Europe/Rome")
		return
	}
	// The Overview draws this next to its request counts, which leave out the
	// internal sources: so does the timeline, or its hours add up to more.
	ext, extArgs := notInternal(h.src.Present())
	// #nosec G202 -- clientRows and ext are constants and placeholders; values are bound.
	rows, err := h.db.Query(string(`
		SELECT (unix_timestamp / 900) * 900 AS quarter,
		       COUNT(*) as total,
		       SUM(blocked) as blocked
		FROM proxy_logs
		WHERE unix_timestamp >= ? AND `+clientRows+` AND `+ext+`
		GROUP BY quarter ORDER BY quarter ASC`),
		append([]any{time.Now().Add(-time.Duration(hours) * time.Hour).Unix()}, extArgs...)...,
	)
	if err != nil {
		writeOK(w, []any{})
		return
	}
	defer rows.Close()
	type hourCount struct {
		start          time.Time
		total, blocked int
	}
	var order []int64
	byStart := map[int64]*hourCount{}
	for rows.Next() {
		var quarter int64
		var total, blocked int
		rows.Scan(&quarter, &total, &blocked) //nolint:errcheck
		t := time.Unix(quarter, 0).In(loc)
		start := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, loc)
		// At the end of summer time the same wall-clock hour comes twice and
		// Date picks the first; a quarter of the second belongs an hour later.
		for t.Sub(start) >= time.Hour {
			start = start.Add(time.Hour)
		}
		key := start.Unix()
		c, seen := byStart[key]
		if !seen {
			c = &hourCount{start: start}
			byStart[key] = c
			order = append(order, key)
		}
		c.total += total
		c.blocked += blocked
	}
	data := make([]map[string]any, 0, len(order))
	for _, key := range order {
		c := byStart[key]
		data = append(data, map[string]any{
			"time": c.start.Format("2006-01-02 15:00:00"), "start": key, "total": c.total, "blocked": c.blocked,
		})
	}
	writeOK(w, data)
}

func (h *LogHandlers) Clear(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(middleware.CtxUsername).(string)
	h.db.Exec("DELETE FROM proxy_logs") //nolint:errcheck
	h.db.Exec("DELETE FROM waf_events") //nolint:errcheck
	h.src.forget()
	h.db.Exec("INSERT INTO audit_log(username,action,target,details) VALUES(?,?,?,?)", username, "clear_logs", "proxy_logs", "") //nolint:errcheck
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "All logs cleared"})
}

func (h *LogHandlers) ClearOld(w http.ResponseWriter, r *http.Request) {
	days := queryInt(r, "days", 30)
	if days < 1 {
		days = 30
	}
	res, err := h.db.Exec("DELETE FROM proxy_logs WHERE timestamp < datetime('now', ?)", "-"+strconv.Itoa(days)+" days") // slopless-disable-line VBC-004 -- the concatenation builds a bound argument, not the statement
	h.db.Exec("DELETE FROM waf_events WHERE timestamp < datetime('now', ?)", "-"+strconv.Itoa(days)+" days")             //nolint:errcheck // slopless-disable-line VBC-004 -- the concatenation builds a bound argument, not the statement
	var deleted int64
	if err == nil && res != nil {
		deleted, _ = res.RowsAffected()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "message": "Cleared old logs", "deleted": deleted,
	})
}

// ── small helpers ─────────────────────────────────────────────────────────────

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func max0(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

// sanitiseSort maps a caller-supplied sort key onto the whitelist, returning
// the DEFAULT for anything not on it.
//
// It returns `a`, the whitelist element, and not `s`, the request parameter
// they compare equal on this path, so the two are interchangeable at runtime —
// but only one of them is a constant this file controls. Returning the
// parameter kept the caller's string alive all the way into the query text,
// which is why CodeQL reported go/sql-injection here (alert on logs.go:67)
// even though the value can only ever be one of six literals. Returning the
// literal makes that provable instead of arguable, to the analyser and to a
// reader, and costs nothing.
func sanitiseSort(s string, allowed []database.SQLText, def database.SQLText) database.SQLText {
	for _, a := range allowed {
		if s == string(a) {
			return a
		}
	}
	return def
}

func sanitiseOrder(s string) database.SQLText {
	if s == "asc" || s == "ASC" {
		return "ASC"
	}
	return "DESC"
}

// nullIfEmpty is nullString with an empty value read as no value.
func nullIfEmpty(s sql.NullString) any {
	if !s.Valid || s.String == "" {
		return nil
	}
	return s.String
}
