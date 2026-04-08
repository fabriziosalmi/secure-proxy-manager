package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

type DatabaseHandlers struct{ db *sql.DB }

func NewDatabaseHandlers(db *sql.DB) *DatabaseHandlers { return &DatabaseHandlers{db: db} }

func (h *DatabaseHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/database/size", h.Size)
	r.With(authMW).Post("/api/database/optimize", h.Optimize)
	r.With(authMW).Get("/api/database/stats", h.Stats)
	r.With(authMW).Get("/api/database/export", h.Export)
	r.With(authMW).Post("/api/database/reset", h.Reset)
}

func (h *DatabaseHandlers) Size(w http.ResponseWriter, r *http.Request) {
	var pageCount, pageSize int64
	h.db.QueryRow("PRAGMA page_count").Scan(&pageCount) //nolint:errcheck
	h.db.QueryRow("PRAGMA page_size").Scan(&pageSize)   //nolint:errcheck
	sizeBytes := pageCount * pageSize
	writeOK(w, map[string]any{"size_bytes": sizeBytes, "size_mb": float64(sizeBytes) / 1e6})
}

func (h *DatabaseHandlers) Optimize(w http.ResponseWriter, r *http.Request) {
	if _, err := h.db.Exec("VACUUM"); err != nil {
		writeError(w, http.StatusInternalServerError, "VACUUM failed")
		return
	}
	if _, err := h.db.Exec("REINDEX"); err != nil {
		writeError(w, http.StatusInternalServerError, "REINDEX failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Database optimized (VACUUM + REINDEX)"})
}

var allowedTables = []string{"users", "ip_whitelist", "ip_blacklist", "domain_blacklist", "domain_whitelist", "proxy_logs", "settings", "audit_log"}

func (h *DatabaseHandlers) Stats(w http.ResponseWriter, r *http.Request) {
	counts := map[string]int64{}
	for _, tbl := range allowedTables {
		var n int64
		// #nosec G202
		h.db.QueryRow("SELECT COUNT(*) FROM " + tbl).Scan(&n) //nolint:errcheck
		counts[tbl] = n
	}
	writeOK(w, counts)
}

func (h *DatabaseHandlers) Export(w http.ResponseWriter, r *http.Request) {
	export := map[string]any{}
	for _, tbl := range allowedTables {
		// #nosec G202
		rows, err := h.db.Query("SELECT * FROM " + tbl)
		if err != nil {
			continue
		}
		cols, _ := rows.Columns()
		var tableRows []map[string]any
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			rows.Scan(ptrs...) //nolint:errcheck
			row := map[string]any{}
			for i, c := range cols {
				// Redact sensitive fields.
				if c == "password" || c == "secret" || c == "token" {
					row[c] = "***REDACTED***"
				} else {
					row[c] = vals[i]
				}
			}
			tableRows = append(tableRows, row)
		}
		rows.Close()
		export[tbl] = tableRows
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=database_export.json")
	json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": export}) //nolint:errcheck
}

func (h *DatabaseHandlers) Reset(w http.ResponseWriter, r *http.Request) {
	// Audit BEFORE wiping (audit_log table will be cleared too)
	username, _ := r.Context().Value(middleware.CtxUsername).(string)
	database.Audit(h.db, username, "database_reset", "all", "full database reset requested")
	for _, tbl := range allowedTables {
		if tbl == "users" {
			continue // Never wipe users.
		}
		// #nosec G202
		h.db.Exec("DELETE FROM " + tbl) //nolint:errcheck
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Database reset (users preserved)"})
}
