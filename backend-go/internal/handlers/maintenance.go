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
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

type MaintenanceHandlers struct {
	db  *sql.DB
	cfg *config.Config
	// reloadAckTimeout bounds the wait for the watchdog's acknowledgement.
	// A field rather than a constant so tests do not have to sleep it out.
	reloadAckTimeout time.Duration
}

func NewMaintenanceHandlers(db *sql.DB, cfg *config.Config) *MaintenanceHandlers {
	return &MaintenanceHandlers{db: db, cfg: cfg, reloadAckTimeout: 8 * time.Second}
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

// backupVersion is the schema of the export envelope. An importer checks it
// rather than guessing from the shape.
const backupVersion = 2

// BackupConfig exports the state worth restoring, not just the toggles.
//
// It used to read the settings table alone, while being presented in the UI and
// README as the product's export/import facility. The omitted set was the
// product's actual content — the IP and domain blacklists, both whitelists and
// the egress allowlist — which an operator accumulates over months and cannot
// reconstruct, unlike a settings map. Someone exporting before a risky change
// and importing afterwards believed they had rolled back and had restored only
// the toggles (SECURE-DATA-04).
//
// The audit log and the users table are deliberately excluded: the first is
// append-only forensic data, the second holds a password hash that has no place
// in a file an operator downloads through a browser.
func (h *MaintenanceHandlers) BackupConfig(w http.ResponseWriter, r *http.Request) {
	settings := map[string]string{}
	rows, err := h.db.Query("SELECT setting_name, setting_value FROM settings")
	if err != nil {
		writeInternalError(w, "backup_config", err)
		return
	}
	for rows.Next() {
		var k, v string
		_ = rows.Scan(&k, &v)
		settings[k] = v
	}
	rows.Close()

	lists := map[string]any{}
	for _, spec := range []struct {
		name, query string
	}{
		{"ip_blacklist", "SELECT ip, COALESCE(description,'') FROM ip_blacklist ORDER BY ip"},
		{"ip_whitelist", "SELECT ip, COALESCE(description,'') FROM ip_whitelist ORDER BY ip"},
		{"domain_blacklist", "SELECT domain, COALESCE(description,'') FROM domain_blacklist ORDER BY domain"},
		{"domain_whitelist", "SELECT domain, COALESCE(description,'') FROM domain_whitelist ORDER BY domain"},
		{"dst_allowlist", "SELECT entry, COALESCE(description,'') FROM dst_allowlist ORDER BY entry"}, // type is re-derived on restore, see restoreEgressType
	} {
		entries := []map[string]string{}
		lrows, err := h.db.Query(spec.query)
		if err != nil {
			writeInternalError(w, "backup_config", err)
			return
		}
		for lrows.Next() {
			var value, desc string
			if err := lrows.Scan(&value, &desc); err == nil {
				entries = append(entries, map[string]string{"value": value, "description": desc})
			}
		}
		lrows.Close()
		lists[spec.name] = entries
	}

	writeOK(w, map[string]any{
		"backup_version": backupVersion,
		"app_version":    config.AppVersion,
		"exported_at":    time.Now().UTC().Format(time.RFC3339),
		"settings":       settings,
		"lists":          lists,
	})
}

func (h *MaintenanceHandlers) RestoreConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		// v1 shape: a bare settings map. Still accepted so an export taken
		// before backup_version 2 can be restored.
		Config map[string]string `json:"config"`
		// v2 shape: settings plus the lists that carry the product's content.
		BackupVersion int                            `json:"backup_version"`
		Settings      map[string]string              `json:"settings"`
		Lists         map[string][]map[string]string `json:"lists"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "no configuration data provided")
		return
	}
	if len(body.Settings) > 0 {
		body.Config = body.Settings
	}
	if len(body.Config) == 0 && len(body.Lists) == 0 {
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
	defer tx.Rollback() //nolint:errcheck // no-op once committed

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
	// Restore the lists in the SAME transaction as the settings, so a partial
	// restore cannot leave the toggles applied and the blacklists not.
	listTargets := map[string][2]string{
		"ip_blacklist":     {"ip_blacklist", "ip"},
		"ip_whitelist":     {"ip_whitelist", "ip"},
		"domain_blacklist": {"domain_blacklist", "domain"},
		"domain_whitelist": {"domain_whitelist", "domain"},
		"dst_allowlist":    {"dst_allowlist", "entry"},
	}
	for name, entries := range body.Lists {
		target, known := listTargets[name]
		if !known {
			log.Warn().Str("list", name).Msg("RestoreConfig: unknown list, skipped")
			continue
		}
		for _, e := range entries {
			value := strings.TrimSpace(e["value"])
			if value == "" {
				continue
			}
			// dst_allowlist.type decides which enforcement file an entry reaches:
			// WHERE type='cidr' goes to dst_allow_ip.txt (a Squid `dst` ACL) and
			// type='domain' to dst_allow_domain.txt (a `dstdomain` ACL). Inserting
			// without it took the column DEFAULT 'domain', so a restored CIDR
			// landed in the domain ACL where dstdomain can never match it — under
			// egress default-deny, a destination the UI lists as allowed and the
			// proxy refuses (SECURE-DOM-01). Re-derived here with the same
			// predicate AddDstAllow uses, so backups already taken without the
			// column are repaired rather than merely no longer broken.
			var err error
			if target[0] == "dst_allowlist" {
				_, err = tx.Exec(
					"INSERT OR IGNORE INTO dst_allowlist(entry, type, description) VALUES(?,?,?)",
					value, egressEntryType(value), e["description"],
				)
			} else {
				_, err = tx.Exec(
					fmt.Sprintf("INSERT OR IGNORE INTO %s(%s, description) VALUES(?,?)", target[0], target[1]),
					value, e["description"],
				)
			}
			if err != nil {
				log.Error().Str("list", name).Err(err).Msg("RestoreConfig: list insert failed — rolling back")
				writeError(w, http.StatusInternalServerError, "failed to restore lists (rolled back)")
				return
			}
			restored++
		}
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit configuration")
		return
	}
	// The lists just changed, so the exported files must be republished.
	workers.RequestExport()

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
	stamp := time.Now().Unix()
	// #nosec G306 — reload trigger, must be readable by the proxy/dns container
	if err := os.WriteFile(reloadFile, []byte(strconv.FormatInt(stamp, 10)), 0644); err != nil {
		log.Warn().Err(err).Msg("proxy reload file trigger failed")
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Config exported — reload trigger write failed, apply manually"})
		return
	}

	// Wait for the watchdog to acknowledge. Writing the trigger and reporting
	// success told the caller nothing: whether the watchdog was alive, whether
	// the generator succeeded and whether squid accepted the config were all
	// invisible, so a user toggling egress default-deny saw a success toast
	// regardless of whether the rule reached Squid (SECURE-ARCH-02).
	res, err := awaitReloadResult(filepath.Join(h.cfg.ConfigDir, ".reload-squid.result"), stamp, h.reloadAckTimeout)
	switch {
	case err != nil:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "pending",
			"message": "reload requested, but the proxy did not acknowledge it in time — check that the proxy container is running",
		})
	case !res.Applied:
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error",
			"code":   "reload_failed",
			"detail": "the proxy refused the new configuration and kept the previous one",
			"data":   map[string]any{"generator_rc": res.GeneratorRC, "reconfigure_rc": res.ReconfigureRC},
		})
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Proxy reloaded"})
	}
}

// reloadResult is the watchdog's acknowledgement of a trigger.
type reloadResult struct {
	TriggerMtime  int64 `json:"trigger_mtime"`
	GeneratorRC   int   `json:"generator_rc"`
	ReconfigureRC *int  `json:"reconfigure_rc"`
	Applied       bool  `json:"applied"`
	At            int64 `json:"at"`
}

// awaitReloadResult polls for an acknowledgement of the trigger written at
// stamp. An older result is ignored, so a stale file cannot be mistaken for an
// answer to this request.
func awaitReloadResult(path string, stamp int64, timeout time.Duration) (reloadResult, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path) // #nosec G304 — fixed internal config path
		if err == nil {
			var res reloadResult
			if json.Unmarshal(data, &res) == nil && res.TriggerMtime >= stamp {
				return res, nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return reloadResult{}, fmt.Errorf("no acknowledgement within %s", timeout)
}

func (h *MaintenanceHandlers) ReloadDNS(w http.ResponseWriter, r *http.Request) {
	if err := database.ExportBlacklistsToFiles(h.db, h.cfg.ConfigDir); err != nil {
		writeInternalError(w, "reload_dns_export", err)
		return
	}
	reloadFile := filepath.Join(h.cfg.ConfigDir, ".reload-dns")
	// #nosec G306 — reload trigger, must be readable by the proxy/dns container
	if err := os.WriteFile(reloadFile, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644); err != nil {
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
	// #nosec G306 — clear-cache trigger, must be readable by the proxy container
	if err := os.WriteFile(clearFile, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644); err != nil {
		log.Warn().Err(err).Msg("clear cache trigger file write failed")
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Proxy cache purge signal sent successfully"})
}
