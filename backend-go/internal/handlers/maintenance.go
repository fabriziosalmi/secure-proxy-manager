package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
	// clearAckTimeout bounds the wait for a cache clear: the watchdog stops
	// Squid, empties the cache_dir, recreates it and starts Squid, which took
	// a few seconds when measured. Below the server's 60 s WriteTimeout.
	clearAckTimeout time.Duration
}

func NewMaintenanceHandlers(db *sql.DB, cfg *config.Config) *MaintenanceHandlers {
	return &MaintenanceHandlers{db: db, cfg: cfg, reloadAckTimeout: 8 * time.Second, clearAckTimeout: 45 * time.Second}
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

	egressProviders := []map[string]any{}
	prows, err := h.db.Query(`SELECT kind, name, url, enabled FROM egress_providers WHERE enabled = 1 OR kind = 'url' ORDER BY kind, name`)
	if err != nil {
		writeInternalError(w, "backup_config", err)
		return
	}
	for prows.Next() {
		var kind, name, rawURL string
		var en int
		if err := prows.Scan(&kind, &name, &rawURL, &en); err == nil {
			egressProviders = append(egressProviders, map[string]any{
				"kind":    kind,
				"name":    name,
				"url":     rawURL,
				"enabled": en == 1,
			})
		}
	}
	prows.Close()

	writeOK(w, map[string]any{
		"backup_version":   backupVersion,
		"app_version":      config.AppVersion,
		"exported_at":      time.Now().UTC().Format(time.RFC3339),
		"settings":         settings,
		"lists":            lists,
		"egress_providers": egressProviders,
	})
}

type backupEgressProvider struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

func (h *MaintenanceHandlers) RestoreConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		// v1 shape: a bare settings map. Still accepted so an export taken
		// before backup_version 2 can be restored.
		Config map[string]string `json:"config"`
		// v2 shape: settings plus the lists that carry the product's content.
		BackupVersion   int                            `json:"backup_version"`
		Settings        map[string]string              `json:"settings"`
		Lists           map[string][]map[string]string `json:"lists"`
		EgressProviders []backupEgressProvider         `json:"egress_providers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "no configuration data provided")
		return
	}
	if len(body.Settings) > 0 {
		body.Config = body.Settings
	}
	if len(body.Config) == 0 && len(body.Lists) == 0 && len(body.EgressProviders) == 0 {
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

	restored, skippedSettings, err := h.restoreSettings(tx, body.Config)
	skipped := len(skippedSettings)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to restore configuration (rolled back)")
		return
	}
	// Restore the lists in the SAME transaction as the settings, so a partial
	// restore cannot leave the toggles applied and the blacklists not.
	perList := map[string]*listRestore{}
	listsRestored, skippedEntries, err := restoreLists(tx, body.Lists, perList)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to restore lists (rolled back)")
		return
	}
	provRestored, provSkipped, err := restoreEgressProviders(tx, body.EgressProviders)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to restore egress providers (rolled back)")
		return
	}
	settingsRestored := restored
	listsRestored += provRestored
	skippedEntries += provSkipped
	restored += listsRestored

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit configuration")
		return
	}
	if len(body.EgressProviders) > 0 {
		cfgDir := ""
		if h.cfg != nil {
			cfgDir = h.cfg.ConfigDir
		}
		username, _ := r.Context().Value(middleware.CtxUsername).(string)
		workers.RefreshEnabledEgressProviders(h.db, cfgDir, username)
	}
	// The lists just changed, so the exported files must be republished.
	workers.RequestExport()

	// The restored settings take effect through the same files a Save writes:
	// the toggle markers, the lists and squid_settings.env. Restore used to
	// write the database only, so a restored toggle showed as on while the
	// proxy kept running without it until some later Save.
	failedFiles := []string{}
	if len(body.Config) > 0 {
		applied := map[string]string{}
		for k, v := range body.Config {
			if isWritableSettingKey(k) && validateSettingValue(k, v) == nil && !appcrypto.IsSensitive(k) {
				applied[k] = v
			}
		}
		sh := &SettingsHandlers{db: h.db, cfg: h.cfg}
		if failed := sh.writeSquidArtefacts(applied); len(failed) > 0 {
			failedFiles = failed
		}
		// The proxy password file follows the stored settings, the password
		// included, which applied leaves out as a secret: a backup that
		// carries only the password still reaches the file.
		if _, ok := body.Config[settingProxyPassword]; ok && !carriesProxyLogin(applied, nil) {
			if failed := sh.syncProxyUsersAndReload(); failed != "" {
				failedFiles = append(failedFiles, failed)
			}
		}
	}

	username, _ := r.Context().Value(middleware.CtxUsername).(string)
	database.Audit(h.db, username, "restore_config", "", fmt.Sprintf("%d settings restored, %d skipped", settingsRestored, skipped))
	// One row per list the backup carried, with the entries that were new
	// and the ones refused. The restore_config row above counts settings only.
	names := make([]string, 0, len(perList))
	for name := range perList {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pl := perList[name]
		auditChange(h.db, r, "restore_"+auditListName(name), "", map[string]any{"added": pl.added, "skipped": pl.skipped})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "success",
		"message":  "Configuration restored successfully",
		"restored": restored,
		"skipped":  skipped,
		// The two halves of restored, so a caller can say what it applied.
		"restored_settings": settingsRestored,
		"restored_entries":  listsRestored,
		// Each setting that was not restored, and why.
		"skipped_settings": skippedSettings,
		// Entries in the lists that failed validation and were not restored.
		"skipped_entries": skippedEntries,
		// Proxy configuration files that could not be written.
		"failed_files": failedFiles,
	})
}

// skippedSetting is a setting in a backup that restore did not apply.
type skippedSetting struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// restoreSettings writes the restorable keys of a backup inside tx. A failed
// write aborts (the caller rolls back); an invalid key is skipped and counted.
func (h *MaintenanceHandlers) restoreSettings(tx *sql.Tx, config map[string]string) (restored int, skipped []skippedSetting, err error) {
	skipped = []skippedSetting{}
	keys := make([]string, 0, len(config))
	for k := range config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := config[k]
		// Same guard as BulkUpdate: only known-safe, writable keys; reject
		// internally-managed state and non-conforming key names. (Previously this
		// path upserted ANY key/value with no validation — a mass-assignment hole.)
		if internallyManagedSettings[k] {
			skipped = append(skipped, skippedSetting{k, "managed by the application, not restored from a file"})
			continue
		}
		if database.IsRetiredSetting(k) {
			skipped = append(skipped, skippedSetting{k, "no longer used by this version, not restored"})
			continue
		}
		if !isWritableSettingKey(k) || len(v) > 10000 {
			log.Warn().Str("key", k).Msg("RestoreConfig: skipping invalid or protected key")
			skipped = append(skipped, skippedSetting{k, "not a valid setting name, or a value longer than 10000 characters"})
			continue
		}
		// The same value rules as the settings API. Restore checked key names
		// only, so a crafted backup stored proxy_port="abc", a negative
		// log_retention_days (which turns off pruning) or a newline-injected
		// bandwidth value that reached the proxy's root shell.
		if err := validateSettingValue(k, v); err != nil {
			log.Warn().Str("key", k).Err(err).Msg("RestoreConfig: skipping a value the settings API would refuse")
			skipped = append(skipped, skippedSetting{k, strings.TrimPrefix(err.Error(), k+": ")})
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
			log.Error().Str("key", k).Err(err).Msg("RestoreConfig: failed to save setting, rolling back")
			return restored, skipped, err
		}
		restored++
	}
	return restored, skipped, nil
}

// listRestore is what a restore did to one list: the entries that were new
// (a duplicate of a stored entry is not counted) and the ones refused.
type listRestore struct {
	added, skipped int64
}

// restoreLists inserts the lists of a backup inside tx, validating each entry
// as its add endpoint would. An invalid entry is skipped and counted; a failed
// insert aborts (the caller rolls back). per, when not nil, receives what
// happened to each known list.
func restoreLists(tx *sql.Tx, lists map[string][]map[string]string, per map[string]*listRestore) (restored, skippedEntries int, err error) {
	listTargets := map[string][2]string{
		"ip_blacklist":     {"ip_blacklist", "ip"},
		"ip_whitelist":     {"ip_whitelist", "ip"},
		"domain_blacklist": {"domain_blacklist", "domain"},
		"domain_whitelist": {"domain_whitelist", "domain"},
		"dst_allowlist":    {"dst_allowlist", "entry"},
	}
	for name, entries := range lists {
		target, known := listTargets[name]
		if !known {
			log.Warn().Str("list", name).Msg("RestoreConfig: unknown list, skipped")
			continue
		}
		// The domain blacklist is bounded by what dnsmasq can hold in memory;
		// a backup from a deployment with a higher limit restores up to it.
		domainRoom := -1
		if name == "domain_blacklist" {
			var n int
			_ = tx.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&n)
			domainRoom = database.DomainBlacklistLimit() - n
		}
		// The entries this restore adds to a list share one "Restore" source,
		// created with the first entry and dropped again if none was new.
		var sourceID int64
		var added, skippedHere int64
		for _, e := range entries {
			value := strings.TrimSpace(e["value"])
			if value == "" {
				continue
			}
			// A backup is a file an operator may have received from anywhere,
			// and these values are written into Squid and dnsmasq files one per
			// line. Apply the checks the add endpoints apply; a value that
			// fails them is skipped and counted, not fatal to the restore
			// (audit: domain-newline-into-hosts-file).
			if !validRestoredListValue(name, value) {
				log.Warn().Str("list", name).Msg("RestoreConfig: skipping an entry that fails validation")
				skippedEntries++
				skippedHere++
				continue
			}
			if domainRoom == 0 {
				skippedEntries++
				skippedHere++
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
			if target[0] == "dst_allowlist" {
				var res sql.Result
				res, err = tx.Exec(
					"INSERT OR IGNORE INTO dst_allowlist(entry, type, description) VALUES(?,?,?)",
					value, egressEntryType(value), e["description"],
				)
				if err == nil {
					n, _ := res.RowsAffected()
					added += n
				}
			} else {
				if sourceID == 0 {
					if sourceID, err = database.NewSource(tx, target[0], database.SourceRestore, ""); err != nil {
						return restored, skippedEntries, err
					}
				}
				var res sql.Result
				res, err = tx.Exec(
					fmt.Sprintf("INSERT OR IGNORE INTO %s(%s, description, source_id) VALUES(?,?,?)", target[0], target[1]),
					value, e["description"], sourceID,
				)
				if err == nil {
					n, _ := res.RowsAffected()
					added += n
				}
			}
			if err != nil {
				log.Error().Str("list", name).Err(err).Msg("RestoreConfig: list insert failed, rolling back")
				return restored, skippedEntries, err
			}
			restored++
			if domainRoom > 0 {
				domainRoom-- // counts a duplicate too: errs towards skipping, never past the limit
			}
		}
		if sourceID != 0 && added == 0 {
			if _, err := tx.Exec("DELETE FROM list_sources WHERE id = ?", sourceID); err != nil {
				return restored, skippedEntries, err
			}
		}
		if per != nil {
			per[name] = &listRestore{added: added, skipped: skippedHere}
		}
	}
	return restored, skippedEntries, nil
}

func restoreEgressProviders(tx *sql.Tx, providers []backupEgressProvider) (restored, skipped int, err error) {
	for _, p := range providers {
		kind := strings.TrimSpace(p.Kind)
		name := strings.TrimSpace(p.Name)
		rawURL := strings.TrimSpace(p.URL)
		switch kind {
		case "catalog":
			if _, ok := workers.LookupCatalogProvider(name); !ok {
				skipped++
				continue
			}
			rawURL = ""
		case "url":
			if name == "" || len(name) > 100 {
				skipped++
				continue
			}
			if _, inCat := workers.LookupCatalogProvider(name); inCat {
				skipped++
				continue
			}
			if ssrf, err := workers.EgressCheckURL(rawURL); err != nil || ssrf {
				skipped++
				continue
			}
		default:
			skipped++
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO egress_providers(kind, name, url, enabled) VALUES(?, ?, ?, ?)
			 ON CONFLICT(kind, name) DO UPDATE SET url = excluded.url, enabled = excluded.enabled`,
			kind, name, rawURL, boolToInt(p.Enabled),
		); err != nil {
			return restored, skipped, err
		}
		restored++
	}
	return restored, skipped, nil
}

// validRestoredListValue applies to a restored list entry the same rule its add
// endpoint applies.
func validRestoredListValue(list, value string) bool {
	switch list {
	case "ip_blacklist":
		return isValidCIDR(value) && !isLANBogonCIDR(value)
	case "ip_whitelist":
		return isValidCIDR(value)
	case "domain_blacklist":
		return isValidDomainEntry(value)
	case "domain_whitelist":
		return isValidHostname(value)
	case "dst_allowlist":
		return egressEntryType(value) == "cidr" || (strings.Contains(value, ".") && isValidDomainEntry(value) && !strings.HasPrefix(value, "*."))
	}
	return false
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
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Config exported, but the reload trigger could not be written; apply manually"})
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
			"message": "reload requested, but the proxy did not acknowledge it in time; check that the proxy container is running",
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
	var res reloadResult
	err := awaitAck(path, stamp, timeout, &res)
	return res, err
}

// awaitAck polls path for the watchdog's acknowledgement of the trigger
// written at stamp and decodes it into out. A result whose trigger_mtime is
// older than stamp answers an earlier request and is ignored.
func awaitAck(path string, stamp int64, timeout time.Duration, out any) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path) // #nosec G304 -- fixed internal config path
		if err == nil {
			var head struct {
				TriggerMtime int64 `json:"trigger_mtime"`
			}
			if json.Unmarshal(data, &head) == nil && head.TriggerMtime >= stamp && json.Unmarshal(data, out) == nil {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("no acknowledgement within %s", timeout)
}

// clearCacheResult is the watchdog's acknowledgement of a cache clear
// (write_clear_result in proxy/blacklist_watchdog.py). Step names where it
// stopped: check (the cache_dir was refused, nothing touched), stop, empty,
// create, start or error; it is null when every step worked.
type clearCacheResult struct {
	TriggerMtime   int64   `json:"trigger_mtime"`
	Applied        bool    `json:"applied"`
	Step           *string `json:"step"`
	Detail         *string `json:"detail"`
	ObjectsRemoved *int    `json:"objects_removed"`
	At             int64   `json:"at"`
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
	stamp := time.Now().Unix()
	// #nosec G306 — clear-cache trigger, must be readable by the proxy container
	if err := os.WriteFile(clearFile, []byte(strconv.FormatInt(stamp, 10)), 0644); err != nil {
		log.Warn().Err(err).Msg("clear cache trigger file write failed")
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "code": "clear_cache_failed",
			"detail": "the clear-cache request could not be written for the proxy",
		})
		return
	}

	// Writing the trigger used to be reported as success. The watchdog's
	// `squid -k purge` was not a command Squid knows, so the disk cache was
	// never emptied while every request said it had been. The watchdog now
	// acknowledges what it did, and this says that.
	var res clearCacheResult
	switch err := awaitAck(filepath.Join(h.cfg.ConfigDir, ".clear-cache.result"), stamp, h.clearAckTimeout, &res); {
	case err != nil:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "pending",
			"message": "clear requested, but the proxy did not answer in time: check that the proxy container is running",
		})
	case !res.Applied:
		detail := "the proxy could not empty its cache"
		if res.Detail != nil && *res.Detail != "" {
			detail = *res.Detail
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "code": "clear_cache_failed", "detail": detail,
			"data": map[string]any{"step": res.Step, "objects_removed": res.ObjectsRemoved},
		})
	default:
		removed := 0
		if res.ObjectsRemoved != nil {
			removed = *res.ObjectsRemoved
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "success",
			"message": fmt.Sprintf("Disk cache emptied (%d objects removed) and Squid restarted", removed),
			"data":    map[string]any{"objects_removed": removed},
		})
	}
}
