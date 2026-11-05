package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// Client groups (database/client_groups.go): sets of clients by address,
// with lists, a time window and allowlist-only egress on top of the policy
// every client gets. A change is exported with the lists; the proxy's
// watchdog sees the groups' index change and regenerates squid.conf.

func (h *BlacklistHandlers) registerClientGroups(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/client-groups", h.listClientGroups)
	r.With(authMW).Post("/api/client-groups", h.saveClientGroup(false))
	r.With(authMW).Get("/api/client-groups/{id}", h.getClientGroup)
	r.With(authMW).Put("/api/client-groups/{id}", h.saveClientGroup(true))
	r.With(authMW).Delete("/api/client-groups/{id}", h.deleteClientGroup)
	for _, l := range listRoutes[:2] { // the IP and domain blacklists
		r.With(authMW).Put("/api/"+l.path+"/sources/{id}/scope", h.setSourceScope(l))
	}
}

func groupID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	return id, err == nil && id > 0
}

func (h *BlacklistHandlers) listClientGroups(w http.ResponseWriter, _ *http.Request) {
	groups, err := database.ListClientGroups(h.db)
	if err != nil {
		writeInternalError(w, "list_client_groups", err)
		return
	}
	writeOK(w, groups)
}

func (h *BlacklistHandlers) getClientGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := groupID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "id must be a group id")
		return
	}
	g, err := database.GetClientGroup(h.db, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	if err != nil {
		writeInternalError(w, "get_client_group", err)
		return
	}
	writeOK(w, g)
}

// saveClientGroup creates a group (POST) or replaces one (PUT .../{id}).
func (h *BlacklistHandlers) saveClientGroup(update bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var g database.ClientGroup
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&g); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		g.ID = 0
		if update {
			id, ok := groupID(r)
			if !ok {
				writeError(w, http.StatusBadRequest, "id must be a group id")
				return
			}
			g.ID = id
		}
		if err := database.NormalizeClientGroup(&g); err != nil {
			writeError(w, http.StatusBadRequest, groupRefusal(err))
			return
		}
		err := database.SaveClientGroup(h.db, &g)
		switch {
		case errors.Is(err, database.ErrGroupInvalid):
			writeError(w, http.StatusBadRequest, groupRefusal(err))
			return
		case errors.Is(err, database.ErrGroupNameTaken):
			writeError(w, http.StatusConflict, "a group named "+strconvQuote(g.Name)+" exists")
			return
		case errors.Is(err, sql.ErrNoRows):
			writeError(w, http.StatusNotFound, "group not found")
			return
		case err != nil:
			writeInternalError(w, "save_client_group", err)
			return
		}
		requestExport()
		action := "add_client_group"
		if update {
			action = "update_client_group"
		}
		auditChange(h.db, r, action, g.Name, map[string]any{
			"members": len(g.Members), "lists": g.Lists, "schedule": g.Schedule, "allowlist_only": g.AllowlistOnly,
		})
		saved, err := database.GetClientGroup(h.db, g.ID)
		if err != nil {
			writeInternalError(w, "save_client_group", err)
			return
		}
		writeOK(w, saved)
	}
}

func (h *BlacklistHandlers) deleteClientGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := groupID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "id must be a group id")
		return
	}
	g, err := database.GetClientGroup(h.db, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	if err != nil {
		writeInternalError(w, "delete_client_group", err)
		return
	}
	if _, err := database.DeleteClientGroup(h.db, id); err != nil {
		writeInternalError(w, "delete_client_group", err)
		return
	}
	requestExport()
	auditChange(h.db, r, "delete_client_group", g.Name, map[string]any{"members": len(g.Members), "lists": g.Lists})
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Group " + strconvQuote(g.Name) + " deleted"})
}

// setSourceScope sets whether a source of a blacklist applies to every
// client ("global") or only to the groups that list it ("groups").
func (h *BlacklistHandlers) setSourceScope(l listRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil || id <= 0 {
			writeError(w, http.StatusBadRequest, "id must be a source id")
			return
		}
		var body struct {
			Scope string `json:"scope"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if body.Scope != database.ScopeGlobal && body.Scope != database.ScopeGroups {
			writeError(w, http.StatusBadRequest, `scope is "global" (every client) or "groups" (only the groups that use it)`)
			return
		}
		err = database.SetSourceScope(h.db, l.table, id, body.Scope)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			writeError(w, http.StatusNotFound, "source not found on this list")
			return
		case errors.Is(err, database.ErrSourceInUse):
			writeError(w, http.StatusConflict, "a group uses this source: take it off the group first")
			return
		case err != nil:
			writeInternalError(w, "set_source_scope", err)
			return
		}
		requestExport()
		auditChange(h.db, r, "set_source_scope_"+l.table, strconv.FormatInt(id, 10), map[string]any{"scope": body.Scope})
		msg := "The source applies to every client"
		if body.Scope == database.ScopeGroups {
			msg = "The source applies only to the groups that use it"
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": msg})
	}
}

// groupRefusal is the user-facing part of a database.ErrGroupInvalid.
func groupRefusal(err error) string {
	return strings.TrimPrefix(err.Error(), database.ErrGroupInvalid.Error()+": ")
}

func strconvQuote(s string) string { return strconv.Quote(s) }
