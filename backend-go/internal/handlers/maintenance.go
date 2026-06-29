package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

type MaintenanceHandlers struct {
	db  *sql.DB
	cfg *config.Config
}

func NewMaintenanceHandlers(db *sql.DB, cfg *config.Config) *MaintenanceHandlers {
	return &MaintenanceHandlers{db: db, cfg: cfg}
}

func (h *MaintenanceHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/maintenance/backup-config", h.BackupConfig)
	r.With(authMW).Post("/api/maintenance/restore-config", h.RestoreConfig)
	r.With(authMW).Get("/api/security/download-ca", h.DownloadCA)
	r.With(authMW).Get("/api/maintenance/check-cert-security", h.CheckCertSecurity)
	r.With(authMW).Post("/api/maintenance/reload-config", h.ReloadConfig)
	r.With(authMW).Post("/api/maintenance/reload-dns", h.ReloadDNS)
	r.With(authMW).Post("/api/maintenance/clear-cache", h.ClearCache)
}

func (h *MaintenanceHandlers) BackupConfig(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT setting_name, setting_value FROM settings")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	settings := map[string]string{}
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v) //nolint:errcheck
		settings[k] = v
	}
	writeOK(w, settings)
}

func (h *MaintenanceHandlers) RestoreConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config map[string]string `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Config) == 0 {
		writeError(w, http.StatusBadRequest, "no configuration data provided")
		return
	}
	// Apply the whole restore atomically: either every valid setting lands or
	// none do, so a mid-restore failure can't leave config half-applied while
	// still reporting success.
	tx, err := h.db.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck — no-op once committed

	restored, skipped := 0, 0
	for k, v := range body.Config {
		// Same guard as BulkUpdate: only known-safe, writable keys; reject
		// internally-managed state and non-conforming key names. (Previously this
		// path upserted ANY key/value with no validation — a mass-assignment hole.)
		if !isWritableSettingKey(k) || len(v) > 10000 {
			log.Warn().Str("key", k).Msg("RestoreConfig: skipping invalid or protected key")
			skipped++
			continue
		}
		val := v
		// Encrypt sensitive values, but NOT if they are already encrypted — a
		// backup exports the raw (already-enc::) column, so re-encrypting here
		// would double-encrypt and corrupt the value on the next decrypt.
		if appcrypto.IsSensitive(k) && val != "" && !appcrypto.IsEncrypted(val) {
			if enc, err := appcrypto.Encrypt(val, h.cfg.EncryptionKey); err == nil {
				val = enc
			}
		}
		if _, err := tx.Exec(
			"INSERT INTO settings(setting_name,setting_value) VALUES(?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value=excluded.setting_value",
			k, val,
		); err != nil {
			log.Error().Str("key", k).Err(err).Msg("RestoreConfig: failed to save setting — rolling back")
			writeError(w, http.StatusInternalServerError, "failed to restore configuration (rolled back)")
			return
		}
		restored++
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit configuration")
		return
	}

	username, _ := r.Context().Value(middleware.CtxUsername).(string)
	database.Audit(h.db, username, "restore_config", "", fmt.Sprintf("%d settings restored, %d skipped", restored, skipped))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "success",
		"message":  "Configuration restored successfully",
		"restored": restored,
		"skipped":  skipped,
	})
}

func (h *MaintenanceHandlers) DownloadCA(w http.ResponseWriter, r *http.Request) {
	certPath := filepath.Join(h.cfg.ConfigDir, "ssl_cert.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "Certificate not found. It may not have been generated yet.")
		return
	}
	// #nosec G304
	f, err := os.Open(certPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open certificate")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=secure-proxy-ca.pem")
	io.Copy(w, f) //nolint:errcheck
}

func (h *MaintenanceHandlers) CheckCertSecurity(w http.ResponseWriter, r *http.Request) {
	var issues []string
	certFound := false
	for _, p := range []string{h.cfg.ConfigDir + "/ssl_cert.pem", "config/ssl_cert.pem"} {
		if _, err := os.Stat(p); err == nil {
			certFound = true
			break
		}
	}
	if !certFound {
		issues = append(issues, "SSL certificate not found")
	}
	dbFound := false
	for _, p := range []string{h.cfg.ConfigDir + "/ssl_db", "config/ssl_db"} {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			if entries, _ := os.ReadDir(p); len(entries) > 0 {
				dbFound = true
				break
			}
		}
	}
	if !dbFound {
		issues = append(issues, "SSL certificate database not found or empty")
	}
	status := "success"
	if len(issues) > 0 {
		status = "error"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": status, "message": "Certificate security check completed",
		"data": map[string]any{"issues": issues, "cert_found": certFound, "db_found": dbFound},
	})
}

func (h *MaintenanceHandlers) ReloadConfig(w http.ResponseWriter, r *http.Request) {
	if err := database.ExportBlacklistsToFiles(h.db, h.cfg.ConfigDir); err != nil {
		log.Warn().Err(err).Msg("export blacklists failed during reload")
	}
	username, _ := r.Context().Value(middleware.CtxUsername).(string)
	database.Audit(h.db, username, "reload_config", "proxy", "")

	reloadFile := filepath.Join(h.cfg.ConfigDir, ".reload-squid")
	if err := os.WriteFile(reloadFile, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644); err != nil { // #nosec G306 — reload trigger, must be readable by the proxy/dns container
		log.Warn().Err(err).Msg("proxy reload file trigger failed")
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Config exported — reload trigger write failed, apply manually"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Proxy reload signal sent successfully"})
}

func (h *MaintenanceHandlers) ReloadDNS(w http.ResponseWriter, r *http.Request) {
	if err := database.ExportBlacklistsToFiles(h.db, h.cfg.ConfigDir); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	reloadFile := filepath.Join(h.cfg.ConfigDir, ".reload-dns")
	if err := os.WriteFile(reloadFile, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644); err != nil { // #nosec G306 — reload trigger, must be readable by the proxy/dns container
		log.Warn().Err(err).Msg("dns reload file trigger failed")
	}
	var count int
	h.db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&count) //nolint:errcheck
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "message": fmt.Sprintf("DNS blocklist updated with %d domains", count),
		"data": map[string]any{"domains": count},
	})
}

func (h *MaintenanceHandlers) ClearCache(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(middleware.CtxUsername).(string)
	database.Audit(h.db, username, "clear_cache", "proxy", "")

	clearFile := filepath.Join(h.cfg.ConfigDir, ".clear-cache")
	if err := os.WriteFile(clearFile, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644); err != nil { // #nosec G306 — clear-cache trigger, must be readable by the proxy container
		log.Warn().Err(err).Msg("clear cache trigger file write failed")
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Proxy cache purge signal sent successfully"})
}
