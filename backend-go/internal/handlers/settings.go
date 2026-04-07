package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

// validKeyRE enforces that settings key names are alphanumeric + underscore only.
var validKeyRE = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

type SettingsHandlers struct {
	db  *sql.DB
	cfg *config.Config
}

func NewSettingsHandlers(db *sql.DB, cfg *config.Config) *SettingsHandlers {
	return &SettingsHandlers{db: db, cfg: cfg}
}

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
		// Decrypt sensitive settings transparently.
		if appcrypto.IsSensitive(k) {
			if dec, err := appcrypto.Decrypt(v, h.cfg.EncryptionKey); err == nil {
				v = dec
			} else {
				log.Warn().Str("key", k).Err(err).Msg("failed to decrypt setting, returning raw")
			}
		}
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
	val := body.Value
	if appcrypto.IsSensitive(name) && val != "" {
		if enc, err := appcrypto.Encrypt(val, h.cfg.EncryptionKey); err == nil {
			val = enc
		} else {
			log.Warn().Str("key", name).Err(err).Msg("failed to encrypt setting")
		}
	}
	_, err := h.db.Exec(
		"INSERT INTO settings(setting_name,setting_value) VALUES(?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value=excluded.setting_value",
		name, val,
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
		// Validate key: max 100 chars, alphanumeric+underscore only (matches DB convention)
		if len(k) > 100 || len(v) > 10000 || !validKeyRE.MatchString(k) {
			log.Warn().Str("key", k).Msg("BulkUpdate: skipping invalid key")
			continue
		}
		val := v
		if appcrypto.IsSensitive(k) && val != "" {
			if enc, err := appcrypto.Encrypt(val, h.cfg.EncryptionKey); err == nil {
				val = enc
			}
		}
		if _, err := h.db.Exec(
			"INSERT INTO settings(setting_name,setting_value) VALUES(?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value=excluded.setting_value",
			k, val,
		); err != nil {
			log.Error().Str("key", k).Err(err).Msg("BulkUpdate: failed to save setting")
		}
	}

	// SSL Bump toggle file — Squid reads this at container startup
	if v, ok := body["ssl_bump_enabled"]; ok {
		toggleFile := filepath.Join(h.cfg.ConfigDir, "ssl_bump_enabled")
		if v == "true" {
			if err := os.WriteFile(toggleFile, []byte("1"), 0o600); err != nil {
				log.Warn().Str("path", toggleFile).Err(err).Msg("ssl_bump toggle file write failed — proxy restart required after fixing permissions")
			}
		} else {
			if err := os.Remove(toggleFile); err != nil && !os.IsNotExist(err) {
				log.Warn().Str("path", toggleFile).Err(err).Msg("ssl_bump toggle file remove failed")
			}
		}
	}

	// Write squid_settings.env so startup.sh can pick up port/cache changes on restart.
	if err := h.writeSquidSettingsEnv(body); err != nil {
		log.Warn().Err(err).Msg("squid_settings.env write failed — proxy restart will use previous values")
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Settings updated"})
}

// writeSquidSettingsEnv writes a shell-sourceable env file to /config/squid_settings.env
// so that startup.sh can apply proxy_port, cache_size, memory_cache on container restart.
func (h *SettingsHandlers) writeSquidSettingsEnv(body map[string]string) error {
	port := h.dbSetting("proxy_port", "3128")
	if v, ok := body["proxy_port"]; ok && v != "" {
		port = v
	}
	cache := h.dbSetting("cache_size", "2000")
	if v, ok := body["cache_size"]; ok && v != "" {
		cache = v
	}
	mem := h.dbSetting("memory_cache", "256")
	if v, ok := body["memory_cache"]; ok && v != "" {
		mem = v
	}
	envContent := "SQUID_PORT=" + port + "\nSQUID_CACHE_MB=" + cache + "\nSQUID_MEM_MB=" + mem + "\n"
	return os.WriteFile(filepath.Join(h.cfg.ConfigDir, "squid_settings.env"), []byte(envContent), 0o600)
}

func (h *SettingsHandlers) dbSetting(key, def string) string {
	var val string
	if err := h.db.QueryRow("SELECT setting_value FROM settings WHERE setting_name=?", key).Scan(&val); err != nil || val == "" {
		return def
	}
	return val
}
