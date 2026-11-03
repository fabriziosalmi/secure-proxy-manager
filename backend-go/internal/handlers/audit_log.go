package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// auditCategories are the filters the Audit page offers. Sign-ins are the
// session events; every other action is a change.
var signInActions = []database.SQLText{"login", "login_failed", "logout"}

// auditCategoryCond is the condition of a category, empty for all of them.
func auditCategoryCond(category string) (cond database.SQLText, ok bool) {
	in := "('" + database.JoinSQL(signInActions, "','") + "')"
	switch category {
	case "", "all":
		return "", true
	case "signins":
		return "action IN " + in, true // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
	case "changes":
		return "(action IS NULL OR action NOT IN " + in + ")", true // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
	}
	return "", false
}

// auditTextCond matches q, as typed, anywhere in who, what, the target or
// the details of a row; the four patterns are bound.
const auditTextCond database.SQLText = `(IFNULL(username, '') LIKE ? ESCAPE '\' OR IFNULL(action, '') LIKE ? ESCAPE '\' ` +
	`OR IFNULL(target, '') LIKE ? ESCAPE '\' OR IFNULL(details, '') LIKE ? ESCAPE '\')`

// auditMaxQuery bounds the text search, in characters (the search field's
// maxLength counts characters too).
const auditMaxQuery = 200

// auditWhere is the WHERE clause of a category and a text search, with the
// values it binds.
func auditWhere(category, q string) (where database.SQLText, args []any, ok bool) {
	cat, ok := auditCategoryCond(category)
	if !ok {
		return "", nil, false
	}
	var conds []database.SQLText
	if cat != "" {
		conds = append(conds, cat)
	}
	if q != "" {
		p := "%" + escapeLike(q) + "%"
		conds = append(conds, auditTextCond)
		args = []any{p, p, p, p}
	}
	if len(conds) == 0 {
		return "", nil, true
	}
	return " WHERE " + database.JoinSQL(conds, " AND "), args, true
}

// AuditLog lists the audit log, newest first, 50 a page. ?category=changes or
// ?category=signins, and ?q= (text in the user, action, target or details),
// narrow it on the server, so the count and the pages are those of the
// filtered log; meta.retention_days is how long a row is kept.
func (h *AnalyticsHandlers) AuditLog(w http.ResponseWriter, r *http.Request) {
	limit := clamp(queryInt(r, "limit", 50), 1, 200)
	offset := max0(queryInt(r, "offset", 0))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if utf8.RuneCountInString(q) > auditMaxQuery {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("q is longer than %d characters", auditMaxQuery))
		return
	}
	where, args, ok := auditWhere(r.URL.Query().Get("category"), q)
	if !ok {
		writeError(w, http.StatusBadRequest, "category must be all, changes or signins")
		return
	}
	// where is built from the constant clauses above; the search text is
	// bound, never part of the SQL text.
	var total int
	if err := h.db.QueryRow(string("SELECT COUNT(*) FROM audit_log"+where), args...).Scan(&total); err != nil { // #nosec G202 -- constant clauses, bound values  // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
		writeInternalError(w, "audit_log_count", err)
		return
	}
	rows, err := h.db.Query(string("SELECT id, username, action, target, details, timestamp FROM audit_log"+where+" ORDER BY id DESC LIMIT ? OFFSET ?"), append(args, limit, offset)...) // #nosec G202 -- constant clauses, bound values  // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
	if err != nil {
		writeInternalError(w, "audit_log", err)
		return
	}
	defer rows.Close()
	entries := []map[string]any{}
	for rows.Next() {
		var id int64
		var username, action, target, details, ts sql.NullString
		if err := rows.Scan(&id, &username, &action, &target, &details, &ts); err != nil {
			continue
		}
		entries = append(entries, map[string]any{
			"id":        id,
			"username":  nullString(username),
			"action":    action.String,
			"target":    nullString(target),
			"details":   nullString(details),
			"timestamp": ts.String,
		})
	}
	days := workers.AuditRetentionDays
	writeList(w, entries, ListMeta{Total: total, Limit: limit, Offset: offset, RetentionDays: &days})
}

func nullString(s sql.NullString) any {
	if !s.Valid {
		return nil
	}
	return s.String
}
