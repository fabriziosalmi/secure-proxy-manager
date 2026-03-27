package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type SettingsHandlers struct{ db *sql.DB }

func NewSettingsHandlers(db *sql.DB) *SettingsHandlers { return &SettingsHandlers{db: db} }

func (h *SettingsHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/settings", h.GetAll)
	r.With(authMW).Put("/api/settings/{name}", h.Update)
	r.With(authMW).Post("/api/settings", h.BulkUpdate)
}

func (h *SettingsHandlers) GetAll(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT setting_name, setting_value FROM settings")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	// Return as array of {setting_name, setting_value} to match Python format
	// (frontend does .forEach on the array)
	type settingRow struct {
		Name  string `json:"setting_name"`
		Value string `json:"setting_value"`
	}
	var settings []settingRow
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v) //nolint:errcheck
		settings = append(settings, settingRow{Name: k, Value: v})
	}
	if settings == nil {
		settings = []settingRow{} // never return null
	}
	writeOK(w, settings)
}

func (h *SettingsHandlers) Update(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(body.Value) > 10000 {
		writeError(w, http.StatusBadRequest, "value too long")
		return
	}
	_, err := h.db.Exec(
		"INSERT INTO settings(setting_name,setting_value) VALUES(?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value=excluded.setting_value",
		name, body.Value,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Setting updated"})
}

func (h *SettingsHandlers) BulkUpdate(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	for k, v := range body {
		// Validate key name: max 100 chars, only alphanumeric + underscore
		if len(k) > 100 || len(v) > 10000 {
			continue
		}
		h.db.Exec( //nolint:errcheck
			"INSERT INTO settings(setting_name,setting_value) VALUES(?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value=excluded.setting_value",
			k, v,
		)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Settings updated"})
}
