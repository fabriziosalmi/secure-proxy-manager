package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

type LogHandlers struct {
	db       *sql.DB
	gdprMu   sync.RWMutex
	gdprVal  bool
	gdprTime time.Time
}

func NewLogHandlers(db *sql.DB) *LogHandlers { return &LogHandlers{db: db} }

func (h *LogHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/logs", h.GetLogs)
	r.With(authMW).Get("/api/logs/stats", h.Stats)
	r.With(authMW).Get("/api/logs/timeline", h.Timeline)
	r.With(authMW).Post("/api/logs/clear", h.Clear)
	r.With(authMW).Post("/api/logs/clear-old", h.ClearOld)
}

func (h *LogHandlers) gdprEnabled() bool {
	const ttl = 30 * time.Second
	h.gdprMu.RLock()
	if time.Since(h.gdprTime) < ttl {
		v := h.gdprVal
		h.gdprMu.RUnlock()
		return v
	}
	h.gdprMu.RUnlock()

	var val string
	enabled := false
	if err := h.db.QueryRow("SELECT setting_value FROM settings WHERE setting_name = 'gdpr_mode'").Scan(&val); err == nil {
		enabled = val == "true"
	}
	h.gdprMu.Lock()
	h.gdprVal = enabled
	h.gdprTime = time.Now()
	h.gdprMu.Unlock()
	return enabled
}

func (h *LogHandlers) GetLogs(w http.ResponseWriter, r *http.Request) {
	limit := clamp(queryInt(r, "limit", 25), 1, 500)
	offset := max0(queryInt(r, "offset", 0))
	sort := sanitiseSort(r.URL.Query().Get("sort"), []string{"timestamp", "source_ip", "destination", "status", "bytes", "method"}, "timestamp")
	order := sanitiseOrder(r.URL.Query().Get("order"))
	gdpr := h.gdprEnabled()

	var total int
	h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs").Scan(&total) //nolint:errcheck

	// sort and order are sanitised against whitelists (sanitiseSort/sanitiseOrder) — safe for interpolation.
	// #nosec G202
	// #nosec G701
	rows, err := h.db.Query(
		"SELECT id,timestamp,source_ip,method,destination,status,bytes FROM proxy_logs ORDER BY "+sort+" "+order+" LIMIT ? OFFSET ?",
		limit, offset,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	var logs []map[string]any
	for rows.Next() {
		var id int64
		var ts, srcIP, method, dest, status sql.NullString
		var bytes sql.NullInt64
		rows.Scan(&id, &ts, &srcIP, &method, &dest, &status, &bytes) //nolint:errcheck
		ip := srcIP.String
		if gdpr {
			ip = maskIP(ip)
		}
		logs = append(logs, map[string]any{
			"id":          id,
			"timestamp":   ts.String,
			"client_ip":   ip,
			"method":      method.String,
			"destination": dest.String,
			"status":      status.String,
			"bytes":       bytes.Int64,
		})
	}
	if logs == nil {
		logs = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "data": logs, "total": total, "limit": limit, "offset": offset,
	})
}

func (h *LogHandlers) Stats(w http.ResponseWriter, r *http.Request) {
	var total, blocked, ipBlocks int
	var lastImport sql.NullString
	h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs").Scan(&total)                                                                               //nolint:errcheck
	h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%'").Scan(&blocked) //nolint:errcheck
	h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE (status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%') AND (destination LIKE 'http://%.%.%.%' OR destination LIKE 'https://%.%.%.%')").Scan(&ipBlocks) //nolint:errcheck
	h.db.QueryRow("SELECT MAX(timestamp) FROM proxy_logs").Scan(&lastImport)                                                                    //nolint:errcheck
	writeOK(w, map[string]any{
		"total_count":    total,
		"blocked_count":  blocked,
		"ip_blocks_count": ipBlocks,
		"last_import":    lastImport.String,
	})
}

func (h *LogHandlers) Timeline(w http.ResponseWriter, r *http.Request) {
	hours := queryInt(r, "hours", 24)
	if hours < 1 || hours > 720 {
		hours = 24
	}
	rows, err := h.db.Query(`
		SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
		       COUNT(*) as total,
		       SUM(CASE WHEN status LIKE '403%' THEN 1 ELSE 0 END) as blocked
		FROM proxy_logs
		WHERE timestamp >= datetime('now', ?)
		GROUP BY hour ORDER BY hour ASC`,
		"-"+strconv.Itoa(hours)+" hours",
	)
	if err != nil {
		writeOK(w, []any{})
		return
	}
	defer rows.Close()
	var data []map[string]any
	for rows.Next() {
		var hour string
		var total, blocked int
		rows.Scan(&hour, &total, &blocked) //nolint:errcheck
		data = append(data, map[string]any{"time": hour, "total": total, "blocked": blocked})
	}
	if data == nil {
		data = []map[string]any{}
	}
	writeOK(w, data)
}

func (h *LogHandlers) Clear(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(middleware.CtxUsername).(string)
	h.db.Exec("DELETE FROM proxy_logs")   //nolint:errcheck
	h.db.Exec("INSERT INTO audit_log(username,action,target,details) VALUES(?,?,?,?)", username, "clear_logs", "proxy_logs", "") //nolint:errcheck
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "All logs cleared"})
}

func (h *LogHandlers) ClearOld(w http.ResponseWriter, r *http.Request) {
	days := queryInt(r, "days", 30)
	if days < 1 {
		days = 30
	}
	res, err := h.db.Exec("DELETE FROM proxy_logs WHERE timestamp < datetime('now', ?)", "-"+strconv.Itoa(days)+" days")
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

func sanitiseSort(s string, allowed []string, def string) string {
	for _, a := range allowed {
		if s == a {
			return s
		}
	}
	return def
}

func sanitiseOrder(s string) string {
	if s == "asc" || s == "ASC" {
		return "ASC"
	}
	return "DESC"
}
