package handlers

import (
	"database/sql"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"net/http"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// auditCategories are the filters the Audit page offers. Sign-ins are the
// session events; every other action is a change.
var signInActions = []database.SQLText{"login", "login_failed", "logout"}

func auditCategoryWhere(category string) (where database.SQLText, ok bool) {
	in := "('" + database.JoinSQL(signInActions, "','") + "')"
	switch category {
	case "", "all":
		return "", true
	case "signins":
		return " WHERE action IN " + in, true
	case "changes":
		return " WHERE action IS NULL OR action NOT IN " + in, true
	}
	return "", false
}

// AuditLog lists the audit log, newest first, 50 a page. ?category=changes or
// ?category=signins narrows it on the server, so the count and the pages are
// those of the filtered log; meta.retention_days is how long a row is kept.
func (h *AnalyticsHandlers) AuditLog(w http.ResponseWriter, r *http.Request) {
	limit := clamp(queryInt(r, "limit", 50), 1, 200)
	offset := max0(queryInt(r, "offset", 0))
	where, ok := auditCategoryWhere(r.URL.Query().Get("category"))
	if !ok {
		writeError(w, http.StatusBadRequest, "category must be all, changes or signins")
		return
	}
	// where is one of the constant clauses above; nothing from the request
	// reaches the SQL text.
	total, err := countRows(h.db, "SELECT COUNT(*) FROM audit_log"+where) // #nosec G202 -- constant clause
	if err != nil {
		writeInternalError(w, "audit_log_count", err)
		return
	}
	rows, err := h.db.Query(string("SELECT id, username, action, target, details, timestamp FROM audit_log"+where+" ORDER BY id DESC LIMIT ? OFFSET ?"), limit, offset) // #nosec G202 -- constant clause
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
