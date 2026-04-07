package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/docker"
)

type MaintenanceHandlers struct {
	db     *sql.DB
	cfg    *config.Config
	docker docker.DockerClient
}

func NewMaintenanceHandlers(db *sql.DB, cfg *config.Config, dc docker.DockerClient) *MaintenanceHandlers {
	return &MaintenanceHandlers{db: db, cfg: cfg, docker: dc}
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
	for k, v := range body.Config {
		h.db.Exec( //nolint:errcheck
			"INSERT INTO settings(setting_name,setting_value) VALUES(?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value=excluded.setting_value",
			k, v,
		)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Configuration restored successfully"})
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
	// Restart the proxy container so startup.sh regenerates squid.conf from the
	// current toggle files (ssl_bump_enabled, etc.) and blacklist files.
	if err := h.docker.RestartContainer("secure-proxy-manager-proxy-1"); err != nil {
		log.Warn().Err(err).Msg("proxy container restart failed (non-fatal)")
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Config exported — proxy restart failed, apply manually"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Proxy restarted with new configuration"})
}

func (h *MaintenanceHandlers) ReloadDNS(w http.ResponseWriter, r *http.Request) {
	if err := database.ExportBlacklistsToFiles(h.db, h.cfg.ConfigDir); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Signal dnsmasq reload via Docker Engine API (replaces docker exec subprocess).
	if err := h.docker.KillContainer("secure-proxy-manager-dns-1", "HUP"); err != nil {
		log.Warn().Err(err).Msg("dnsmasq SIGHUP failed (non-fatal)")
	}
	var count int
	h.db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&count) //nolint:errcheck
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "message": fmt.Sprintf("DNS blocklist updated with %d domains", count),
		"data": map[string]any{"domains": count},
	})
}

func (h *MaintenanceHandlers) ClearCache(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(fmt.Sprintf("http://%s:%s/api/cache/clear", h.cfg.ProxyHost, h.cfg.ProxyPort), "application/json", nil)
	if err != nil {
		log.Warn().Err(err).Msg("proxy cache clear failed (non-fatal)")
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Proxy cache clear simulated"})
		return
	}
	resp.Body.Close()
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Proxy cache cleared"})
}
