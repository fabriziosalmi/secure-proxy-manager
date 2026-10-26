package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

type EgressProviderHandlers struct {
	db  *sql.DB
	cfg *config.Config
}

func NewEgressProviderHandlers(db *sql.DB, cfg *config.Config) *EgressProviderHandlers {
	return &EgressProviderHandlers{db: db, cfg: cfg}
}

func (h *EgressProviderHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/egress-providers", h.GetAll)
	r.With(authMW).Post("/api/egress-providers/url", h.AddURL)
	r.With(authMW).Delete("/api/egress-providers/url/{id}", h.DeleteURL)
	r.With(authMW).Put("/api/egress-providers/{name}", h.SetEnabled)
	r.With(authMW).Post("/api/egress-providers/{name}/refresh", h.Refresh)
	r.With(authMW).Post("/api/egress-providers/{name}/apply-held", h.ApplyHeld)
}

func registerEgressProvidersOnRouter(r chi.Router, db *sql.DB, cfg *config.Config, authMW func(http.Handler) http.Handler) {
	NewEgressProviderHandlers(db, cfg).Register(r, authMW)
}

func (h *EgressProviderHandlers) resolveProvider(name string) (kind string, shared bool, ok bool) {
	if cat, found := workers.LookupCatalogProvider(name); found {
		return "catalog", cat.SharedNetwork, true
	}
	var id int64
	if err := h.db.QueryRow(`SELECT id FROM egress_providers WHERE kind = 'url' AND name = ?`, name).Scan(&id); err == nil {
		return "url", false, true
	}
	return "", false, false
}

func (h *EgressProviderHandlers) exportNow() {
	if h.cfg != nil && h.cfg.ConfigDir != "" {
		if err := database.ExportBlacklistsToFiles(h.db, h.cfg.ConfigDir); err == nil {
			metrics.ExportSuccess()
		} else {
			metrics.ExportFailure()
		}
	}
	requestExport()
}

func (h *EgressProviderHandlers) GetAll(w http.ResponseWriter, _ *http.Request) {
	providers, err := workers.ListEgressProviders(h.db)
	if err != nil {
		writeInternalError(w, "list_egress_providers", err)
		return
	}
	writeOK(w, providers)
}

func (h *EgressProviderHandlers) SetEnabled(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(chi.URLParam(r, "name"))
	kind, shared, ok := h.resolveProvider(name)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown egress provider %q", name))
		return
	}

	var req struct {
		Enabled       *bool `json:"enabled"`
		ConfirmShared bool  `json:"confirm_shared"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled (boolean) is required")
		return
	}

	if *req.Enabled && shared && !req.ConfirmShared {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("provider %q is a shared network where third-party workloads run; set confirm_shared to true to confirm", name))
		return
	}

	if _, err := h.db.Exec(
		`INSERT INTO egress_providers(kind, name, enabled) VALUES(?, ?, ?)
		 ON CONFLICT(kind, name) DO UPDATE SET enabled = excluded.enabled`,
		kind, name, boolToInt(*req.Enabled),
	); err != nil {
		writeInternalError(w, "set_egress_provider_enabled", err)
		return
	}

	var pid int64
	var entryCount int
	_ = h.db.QueryRow(`SELECT id FROM egress_providers WHERE kind = ? AND name = ?`, kind, name).Scan(&pid)
	if pid > 0 {
		_ = h.db.QueryRow(`SELECT COUNT(*) FROM egress_provider_entries WHERE provider_id = ?`, pid).Scan(&entryCount)
	}

	if *req.Enabled {
		auditChange(h.db, r, "egress_provider_enabled", name, map[string]any{
			"kind":           kind,
			"shared_network": shared,
		})
		if entryCount == 0 {
			cfgDir := ""
			if h.cfg != nil {
				cfgDir = h.cfg.ConfigDir
			}
			st, held, refreshErr := workers.RefreshEgressProvider(h.db, cfgDir, kind, name, requestUser(r))
			if refreshErr != nil {
				st, err := workers.GetEgressProviderState(h.db, kind, name)
				if err != nil {
					writeInternalError(w, "get_egress_provider", err)
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{
					"status":        "success",
					"data":          st,
					"held":          false,
					"refresh_error": refreshErr.Error(),
				})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"status": "success",
				"data":   st,
				"held":   held,
			})
			return
		}
	} else {
		auditChange(h.db, r, "egress_provider_disabled", name, map[string]any{
			"kind": kind,
		})
	}

	h.exportNow()
	st, err := workers.GetEgressProviderState(h.db, kind, name)
	if err != nil {
		writeInternalError(w, "get_egress_provider", err)
		return
	}
	writeOK(w, st)
}

func (h *EgressProviderHandlers) AddURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL   string `json:"url"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	label := strings.TrimSpace(req.Label)
	rawURL := strings.TrimSpace(req.URL)
	if label == "" || len(label) > 100 {
		writeError(w, http.StatusBadRequest, "label must be between 1 and 100 characters")
		return
	}
	if _, inCatalog := workers.LookupCatalogProvider(label); inCatalog {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("%q is a reserved catalog provider name", label))
		return
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		writeError(w, http.StatusBadRequest, "url must be a valid http or https URL")
		return
	}
	if ssrf, err := workers.EgressCheckURL(rawURL); err != nil || ssrf {
		writeError(w, http.StatusBadRequest, "url resolves to a private or disallowed address")
		return
	}

	res, err := h.db.Exec(
		`INSERT INTO egress_providers(kind, name, url, enabled) VALUES('url', ?, ?, 1)`,
		label, rawURL,
	)
	if err != nil {
		writeError(w, http.StatusConflict, "a URL provider with that label or URL already exists")
		return
	}
	pid, _ := res.LastInsertId()

	auditChange(h.db, r, "egress_provider_enabled", label, map[string]any{
		"kind": "url",
		"url":  redactURL(rawURL),
	})

	cfgDir := ""
	if h.cfg != nil {
		cfgDir = h.cfg.ConfigDir
	}
	st, held, err := workers.RefreshEgressProvider(h.db, cfgDir, "url", label, requestUser(r))
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("provider saved (id %d) but initial refresh failed: %v", pid, err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   st,
		"held":   held,
	})
}

func (h *EgressProviderHandlers) DeleteURL(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid provider id")
		return
	}
	var name, rawURL string
	if err := h.db.QueryRow(`SELECT name, url FROM egress_providers WHERE id = ? AND kind = 'url'`, id).Scan(&name, &rawURL); err != nil {
		writeError(w, http.StatusNotFound, "URL provider not found")
		return
	}

	tx, err := h.db.Begin()
	if err != nil {
		writeInternalError(w, "delete_egress_provider_url", err)
		return
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(`DELETE FROM egress_provider_entries WHERE provider_id = ?`, id); err != nil {
		writeInternalError(w, "delete_egress_provider_entries", err)
		return
	}
	if _, err := tx.Exec(`DELETE FROM egress_providers WHERE id = ? AND kind = 'url'`, id); err != nil {
		writeInternalError(w, "delete_egress_provider_url", err)
		return
	}
	if err := tx.Commit(); err != nil {
		writeInternalError(w, "commit_delete_egress_provider_url", err)
		return
	}

	metrics.DeleteEgressProviderEntries(name)
	auditChange(h.db, r, "egress_provider_disabled", name, map[string]any{
		"kind":    "url",
		"url":     redactURL(rawURL),
		"deleted": true,
	})
	h.exportNow()
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": fmt.Sprintf("Removed URL provider %s", name)})
}

func (h *EgressProviderHandlers) Refresh(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(chi.URLParam(r, "name"))
	kind, _, ok := h.resolveProvider(name)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown egress provider %q", name))
		return
	}
	cfgDir := ""
	if h.cfg != nil {
		cfgDir = h.cfg.ConfigDir
	}
	st, held, err := workers.RefreshEgressProvider(h.db, cfgDir, kind, name, requestUser(r))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   st,
		"held":   held,
	})
}

func (h *EgressProviderHandlers) ApplyHeld(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(chi.URLParam(r, "name"))
	kind, _, ok := h.resolveProvider(name)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown egress provider %q", name))
		return
	}
	cfgDir := ""
	if h.cfg != nil {
		cfgDir = h.cfg.ConfigDir
	}
	st, err := workers.ApplyHeldEgressProvider(h.db, cfgDir, kind, name, requestUser(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, st)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
