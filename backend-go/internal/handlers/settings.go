package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

// settingValidators gives the values a server-side domain. The table was
// TEXT-to-TEXT with no per-key validation, so the only shape checking for
// ports, emails and booleans was a zod schema running in the BROWSER — bypassed
// by any direct API call. proxy_port='abc' was persisted and then written into
// the file Squid's config generator sources (SECURE-DOM-06).
var settingValidators = map[string]func(string) error{
	"proxy_port":           validPort,
	"cache_size":           validNonNegativeInt,
	"memory_cache":         validNonNegativeInt,
	"log_retention_days":   validPositiveInt,
	"bandwidth_limit_mbps": validPositiveInt,
	// Both reach a file the proxy reads as root and had no rule at all:
	// a newline in the first and letters in the second were stored and
	// written out.
	"bandwidth_limit_per_user_kbps": validNonNegativeInt,
	"extra_ssl_ports":               validPortList,
	"time_restriction_start":        validTimeOfDay,
	"time_restriction_end":          validTimeOfDay,
	"admin_email":                   validEmailOrEmpty,
}

func validPort(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("must be a port between 1 and 65535")
	}
	return nil
}

// portListRE is what the proxy's generator accepts for EXTRA_SSL_PORTS.
var portListRE = regexp.MustCompile(`^\s*([0-9]{1,5}([ ,]+[0-9]{1,5})*)?\s*$`)

// validPortList accepts an empty value or ports separated by commas or spaces.
func validPortList(v string) error {
	if !portListRE.MatchString(v) {
		return fmt.Errorf("must be port numbers separated by commas or spaces")
	}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if err := validPort(f); err != nil {
			return err
		}
	}
	return nil
}

func validNonNegativeInt(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fmt.Errorf("must be a non-negative number")
	}
	return nil
}

func validPositiveInt(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fmt.Errorf("must be a positive number")
	}
	return nil
}

func validTimeOfDay(v string) error {
	if !timeOfDayRE.MatchString(v) {
		return fmt.Errorf("must be a time of day as HH:MM")
	}
	return nil
}

func validEmailOrEmpty(v string) error {
	if v == "" {
		return nil
	}
	if _, err := mail.ParseAddress(v); err != nil {
		return fmt.Errorf("must be a valid email address")
	}
	return nil
}

// validateSettingValue applies the value domain for a key, if it has one. Keys
// without an entry are free-form text, bounded only by length.
func validateSettingValue(key, value string) error {
	if fn, ok := settingValidators[key]; ok {
		if err := fn(value); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return nil
}

// validKeyRE enforces that settings key names are alphanumeric + underscore only.
var validKeyRE = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// timeOfDayRE bounds the values written into /config/time_restrictions.conf,
// which the proxy sources as shell.
var timeOfDayRE = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

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
		writeInternalError(w, "list_settings", err)
		return
	}
	defer rows.Close()
	// Return as array of {setting_name, setting_value} to match Python format
	// (frontend does .forEach on the array)
	type settingRow struct {
		Name  string `json:"setting_name"`
		Value string `json:"setting_value"`
		// Secret marks a write-only setting (crypto.SensitiveKeys). Its value
		// is never returned: the page shows whether one is stored and the
		// operator can replace or clear it, not read it back.
		Secret bool `json:"secret,omitempty"`
		// IsSet says a secret has a stored value, readable or not.
		IsSet bool `json:"is_set,omitempty"`
		// DecryptFailed marks a stored secret that could not be decrypted
		// (wrong or rotated key). The UI must render it as unreadable and must
		// not submit it back, or the Save would overwrite the secret.
		DecryptFailed bool `json:"decrypt_failed,omitempty"`
	}
	var settings []settingRow
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v) //nolint:errcheck
		if !appcrypto.IsSensitive(k) {
			settings = append(settings, settingRow{Name: k, Value: v})
			continue
		}
		// Secrets are write-only. Returning the plaintext put every channel
		// token in the browser and in any proxy that logs responses, and
		// returning the raw enc:: blob of an unreadable one would put
		// ciphertext in the form, which the next Save re-encrypted as if it
		// were the plaintext (SECURE-ERR-06). The decrypt is still attempted
		// so an unreadable value is flagged.
		row := settingRow{Name: k, Secret: true, IsSet: v != ""}
		if v != "" {
			if _, err := appcrypto.Decrypt(v, h.cfg.EncryptionKey); err != nil {
				log.Error().Str("key", k).Err(err).Msg("failed to decrypt setting: flagged as unreadable")
				row.DecryptFailed = true
			}
		}
		settings = append(settings, row)
	}
	if settings == nil {
		settings = []settingRow{} // never return null
	}
	writeOK(w, settings)
}

func (h *SettingsHandlers) Update(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	// isWritableSettingKey subsumes the length and character checks AND rejects
	// internally-managed keys. Previously this path checked only the shape, so
	// PUT /api/settings/default_password_changed could rewrite trusted internal
	// state that BulkUpdate and RestoreConfig both refuse (SECURE-DOM-04).
	if !isWritableSettingKey(name) {
		writeError(w, http.StatusBadRequest, "invalid or protected setting name")
		return
	}
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
	if err := validateSettingValue(name, body.Value); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	val := body.Value
	if appcrypto.IsSensitive(name) && val != "" {
		enc, err := appcrypto.Encrypt(val, h.cfg.EncryptionKey)
		if err != nil {
			// Refuse rather than downgrade. Storing a value the project itself
			// classifies as sensitive in cleartext, and reporting success, is
			// worse than failing the write (SECURE-ERR-04).
			log.Error().Str("key", name).Err(err).Msg("refusing to store sensitive setting: encryption failed")
			writeError(w, http.StatusInternalServerError, "encryption unavailable — sensitive setting not saved")
			return
		}
		val = enc
	}
	_, err := h.db.Exec(
		"INSERT INTO settings(setting_name,setting_value) VALUES(?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value=excluded.setting_value",
		name, val,
	)
	if err != nil {
		writeInternalError(w, "update_setting", err)
		return
	}
	if user, ok := r.Context().Value(middleware.CtxUsername).(string); ok {
		database.Audit(h.db, user, "update_setting", name, "")
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Setting updated"})
}

// BulkUpdate saves a batch of settings and then fans the result out to the
// artefacts that make those settings take effect. The three phases are kept
// separate deliberately: the database is authoritative and committed first, the
// artefacts are best-effort and reported, and only the artefact phase may
// partially fail (SECURE-QUAL-01).
func (h *SettingsHandlers) BulkUpdate(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	clearKeys, msg := parseClearList(r.URL.Query().Get("clear"), body)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if body == nil {
		body = map[string]string{}
	}
	for k := range clearKeys {
		body[k] = ""
	}
	h.auditBulkUpdate(r, body)

	kept, status, msg := h.persistSettings(body, clearKeys)
	if status != 0 {
		writeError(w, status, msg)
		return
	}

	// Push heuristic toggles to the running WAF so they take effect immediately —
	// the WAF otherwise only reads WAF_H_* env at startup (issue #102).
	h.pushHeuristicsToWAF(r.Context(), body)

	// The handler reads as settings persistence and is in fact a fan-out: after
	// the transaction it writes six configuration artefacts and makes an
	// outbound call to the WAF. Every one of those writes used to be discarded,
	// so a full disk or a read-only /config produced a 200 while the artefacts
	// that make the settings take effect did not exist (SECURE-QUAL-03).
	if failedArtifacts := h.writeSquidArtefacts(body); len(failedArtifacts) > 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "partial",
			"message": "settings saved, but some proxy configuration files could not be written",
			"data":    map[string]any{"failed": failedArtifacts, "kept": kept},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": "Settings updated",
		"data":    map[string]any{"kept": kept},
	})
}

// parseClearList reads the clear query parameter: the secrets the caller
// asks to remove. Only a secret can be cleared this way, and a secret cannot
// be cleared and given a value in the same request. It returns the set, or
// the message for a 400.
func parseClearList(raw string, body map[string]string) (map[string]bool, string) {
	clearKeys := map[string]bool{}
	for _, k := range strings.Split(raw, ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if !appcrypto.IsSensitive(k) {
			return nil, "clear: " + k + " is not a secret setting"
		}
		if body[k] != "" {
			return nil, k + ": cannot be cleared and set in the same request"
		}
		clearKeys[k] = true
	}
	return clearKeys, ""
}

// auditBulkUpdate records the attempt with the key names — never the values,
// which may be secrets — before anything is written.
func (h *SettingsHandlers) auditBulkUpdate(r *http.Request, body map[string]string) {
	user, ok := r.Context().Value(middleware.CtxUsername).(string)
	if !ok || len(body) == 0 {
		return
	}
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	database.Audit(h.db, user, "update_settings", strings.Join(keys, ","), "")
}

// persistSettings writes every writable key in body inside a single transaction,
// so a mid-loop failure cannot leave the database half-updated relative to the
// artefacts written afterwards. A secret sent empty keeps its stored value
// unless clear names it, and is returned in kept. It returns status 0 on
// success, or the HTTP status and message the caller must send.
func (h *SettingsHandlers) persistSettings(body map[string]string, clearKeys map[string]bool) (kept []string, status int, msg string) {
	kept = []string{}
	tx, err := h.db.Begin()
	if err != nil {
		return kept, http.StatusInternalServerError, "failed to start transaction"
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	for k, v := range body {
		// Only known-safe, writable keys may be set (rejects internally-managed
		// state like default_password_changed and any non-conforming key name).
		if !isWritableSettingKey(k) || len(v) > 10000 {
			log.Warn().Str("key", k).Msg("BulkUpdate: skipping invalid or protected key")
			continue
		}
		// A secret is write-only, so a form that did not touch it sends it
		// empty, and an unreadable one comes back empty from GET. Storing that
		// empty value wiped the secret on the next Save of any other setting.
		// Only an explicit clear removes it.
		if appcrypto.IsSensitive(k) && v == "" && !clearKeys[k] {
			var stored string
			if err := tx.QueryRow("SELECT setting_value FROM settings WHERE setting_name=?", k).Scan(&stored); err == nil && stored != "" {
				kept = append(kept, k)
			}
			continue
		}
		if err := validateSettingValue(k, v); err != nil {
			return kept, http.StatusBadRequest, err.Error()
		}
		val := v
		if appcrypto.IsSensitive(k) && val != "" && !appcrypto.IsEncrypted(val) {
			if enc, err := appcrypto.Encrypt(val, h.cfg.EncryptionKey); err == nil {
				val = enc
			}
		}
		if _, err := tx.Exec(
			"INSERT INTO settings(setting_name,setting_value) VALUES(?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value=excluded.setting_value",
			k, val,
		); err != nil {
			log.Error().Str("key", k).Err(err).Msg("BulkUpdate: failed to save setting — rolling back")
			return kept, http.StatusInternalServerError, "failed to save settings (rolled back)"
		}
	}
	if err := tx.Commit(); err != nil {
		return kept, http.StatusInternalServerError, "failed to commit settings"
	}
	sort.Strings(kept)
	return kept, 0, ""
}

// writeSquidArtefacts writes the /config files the proxy reads, and names the
// ones that could not be written. Only the env file and the two ACL lists are
// reported: the rest are advisory and already logged where they fail.
func (h *SettingsHandlers) writeSquidArtefacts(body map[string]string) []string {
	var failedArtifacts []string

	h.writeToggleFiles(body)

	// Cache bypass domains — Squid matches a dstdomain ACL, which needs the
	// leading dot to cover subdomains.
	if v, ok := body["cache_bypass_domains"]; ok {
		if err := h.writeListArtefact("cache_bypass_domains.txt", v, func(d string) string {
			return "." + strings.TrimPrefix(d, ".")
		}); err != nil {
			log.Warn().Err(err).Msg("ssl bypass list write failed")
			failedArtifacts = append(failedArtifacts, "ssl_bypass_domains.txt")
		}
	}

	// Blocked file types — Squid matches a urlpath_regex ACL, so each extension
	// becomes an anchored pattern.
	if v, ok := body["blocked_file_types"]; ok {
		if err := h.writeListArtefact("blocked_file_types.txt", v, func(ext string) string {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			return `\` + ext + `$`
		}); err != nil {
			log.Warn().Err(err).Msg("blocked file types write failed")
			failedArtifacts = append(failedArtifacts, "blocked_file_types.txt")
		}
	}

	// Write time restriction settings for Squid time ACL.
	if _, ok := body["enable_time_restrictions"]; ok {
		h.writeTimeRestrictions(body)
	}

	// Write bandwidth limit settings for Squid delay_pools.
	if _, ok := body["enable_bandwidth_limits"]; ok {
		h.writeBandwidthSettings(body)
	}

	// Write squid_settings.env so startup.sh can pick up port/cache changes on restart.
	if err := h.writeSquidSettingsEnv(body); err != nil {
		log.Warn().Err(err).Msg("squid_settings.env write failed — proxy restart will use previous values")
		failedArtifacts = append(failedArtifacts, "squid_settings.env")
	}
	return failedArtifacts
}

// squidToggleFiles maps a boolean setting to the marker file Squid's startup
// reads. Presence is the signal; the content is never parsed.
var squidToggleFiles = []struct {
	key  string
	file string
}{
	{"ssl_bump_enabled", "ssl_bump_enabled"},
	{"egress_default_deny", "egress_default_deny"},
	{"aggressive_caching_enabled", "aggressive_caching_enabled"},
	{"enable_offline_mode", "offline_mode_enabled"},
	{"enable_content_filtering", "content_filtering_enabled"},
	{"enable_safesearch", "safesearch_enabled"},
	{"enable_youtube_restricted", "youtube_restricted_enabled"},
	{"enable_proxy_auth", "proxy_auth_enabled"},
	{"enable_bandwidth_limits", "bandwidth_limits_enabled"},
	{"enable_time_restrictions", "time_restrictions_enabled"},
}

// writeToggleFiles creates or removes the marker files for the toggles present
// in body. Failures are logged and not reported: a stale marker only survives
// until the next successful save, and Squid reads them at startup.
func (h *SettingsHandlers) writeToggleFiles(body map[string]string) {
	for _, tg := range squidToggleFiles {
		v, ok := body[tg.key]
		if !ok {
			continue
		}
		toggleFile := filepath.Join(h.cfg.ConfigDir, tg.file)
		if v == "true" {
			if err := os.WriteFile(toggleFile, []byte("1"), 0o600); err != nil {
				log.Warn().Str("path", toggleFile).Err(err).Msg("toggle file write failed")
			}
			continue
		}
		if err := os.Remove(toggleFile); err != nil && !os.IsNotExist(err) {
			log.Warn().Str("path", toggleFile).Err(err).Msg("toggle file remove failed")
		}
	}
}

// writeListArtefact writes a comma-separated setting as the newline-separated
// file a Squid ACL loads, applying transform to each non-empty element. An
// empty value removes the file, so clearing a list in the UI cannot leave a
// stale ACL enforcing the old one.
func (h *SettingsHandlers) writeListArtefact(file, value string, transform func(string) string) error {
	path := filepath.Join(h.cfg.ConfigDir, file)
	if value == "" {
		os.Remove(path) //nolint:errcheck
		return nil
	}
	var items []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(strings.ToLower(item))
		if item != "" {
			items = append(items, transform(item))
		}
	}
	return os.WriteFile(path, []byte(strings.Join(items, "\n")+"\n"), 0o600)
}

// heuristicSettingKeys are the WAF heuristic toggles that must be propagated to
// the running WAF, which otherwise only reads WAF_H_* env at startup. Keep in
// sync with the WAF's heuristicToggles map (waf-go/heuristics.go).
var heuristicSettingKeys = map[string]bool{
	"waf_h_entropy":   true,
	"waf_h_beaconing": true,
	"waf_h_pii":       true,
	"waf_h_sharding":  true,
	"waf_h_ghosting":  true,
	"waf_h_sequence":  true,
}

// pushHeuristicsToWAF propagates any heuristic toggles in the just-saved settings
// to the WAF's runtime config (POST /heuristics/toggle). Best-effort: the DB is
// the source of truth, so a WAF hiccup is logged but never fails the save.
//
// The database is authoritative and a restarted WAF is brought back to it by
// workers.StartWAFReconciler. This comment used to claim the value "still
// applies on the WAF's next restart via WAF_H_* env" — it does not: those
// variables come from the compose file and never carry the stored value, so a
// WAF restart silently reverted every toggle to the compose default while the
// UI kept showing the operator's choice (SECURE-CONF-02).
func (h *SettingsHandlers) pushHeuristicsToWAF(ctx context.Context, body map[string]string) {
	for key, val := range body {
		if !heuristicSettingKeys[key] {
			continue
		}
		payload, err := json.Marshal(map[string]any{"heuristic": key, "enabled": val == "true"})
		if err != nil {
			continue
		}
		resp, err := wafPostBreaker(ctx, h.cfg, "/heuristics/toggle", "application/json", bytes.NewReader(payload))
		if err != nil {
			log.Warn().Str("key", key).Err(err).Msg("failed to push heuristic toggle to WAF — applies on WAF restart")
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Warn().Str("key", key).Int("status", resp.StatusCode).Msg("WAF rejected heuristic toggle")
		}
		resp.Body.Close() //nolint:errcheck
	}
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
	extraSSL := h.dbSetting("extra_ssl_ports", "")
	if v, ok := body["extra_ssl_ports"]; ok {
		extraSSL = v
	}
	// Validated, not filtered. The filter kept letters and spaces, so
	// "8443 pkill squid" was written as-is, and the generator used to source
	// this file as root. Each value must have the shape the generator accepts.
	if validPort(port) != nil || validNonNegativeInt(cache) != nil || validNonNegativeInt(mem) != nil || validPortList(extraSSL) != nil {
		return fmt.Errorf("invalid proxy settings in the database — squid_settings.env not written")
	}
	envContent := "SQUID_PORT=" + port + "\nSQUID_CACHE_MB=" + cache + "\nSQUID_MEM_MB=" + mem + "\nEXTRA_SSL_PORTS=" + strings.TrimSpace(extraSSL) + "\n"
	return os.WriteFile(filepath.Join(h.cfg.ConfigDir, "squid_settings.env"), []byte(envContent), 0o600)
}

// writeTimeRestrictions writes a config file with time restriction settings
// so that startup.sh can generate Squid time ACLs.
func (h *SettingsHandlers) writeTimeRestrictions(body map[string]string) {
	start := h.dbSetting("time_restriction_start", "08:00")
	if v, ok := body["time_restriction_start"]; ok && v != "" {
		start = v
	}
	end := h.dbSetting("time_restriction_end", "18:00")
	if v, ok := body["time_restriction_end"]; ok && v != "" {
		end = v
	}
	// These values are written into a file the proxy's ROOT shell sources.
	// safe_source rejects shell metacharacters but permits any KEY=VALUE, so an
	// unsanitised newline injects an arbitrary variable assignment (PATH, IFS)
	// into that shell. A time is HH:MM and nothing else (audit: domain-newline-into-hosts-file).
	if !timeOfDayRE.MatchString(start) || !timeOfDayRE.MatchString(end) {
		log.Warn().Str("start", start).Str("end", end).Msg("invalid time restriction values — not written")
		return
	}
	content := "TIME_START=" + start + "\nTIME_END=" + end + "\n"
	os.WriteFile(filepath.Join(h.cfg.ConfigDir, "time_restrictions.conf"), []byte(content), 0o600) //nolint:errcheck
}

// writeBandwidthSettings writes bandwidth limit config for Squid delay_pools.
func (h *SettingsHandlers) writeBandwidthSettings(body map[string]string) {
	limitMbps := h.dbSetting("bandwidth_limit_mbps", "100")
	if v, ok := body["bandwidth_limit_mbps"]; ok && v != "" {
		limitMbps = v
	}
	perUserKbps := h.dbSetting("bandwidth_limit_per_user_kbps", "0")
	if v, ok := body["bandwidth_limit_per_user_kbps"]; ok && v != "" {
		perUserKbps = v
	}
	// Checked again here, not only on the way in: a value already in the
	// database (an older version, a restore) must not reach this file.
	if validPositiveInt(limitMbps) != nil || validNonNegativeInt(perUserKbps) != nil {
		log.Warn().Msg("invalid bandwidth limit values in the database — bandwidth_limits.conf not written")
		return
	}
	content := "BW_LIMIT_MBPS=" + limitMbps + "\nBW_PER_USER_KBPS=" + perUserKbps + "\n"
	os.WriteFile(filepath.Join(h.cfg.ConfigDir, "bandwidth_limits.conf"), []byte(content), 0o600) //nolint:errcheck
}

func (h *SettingsHandlers) dbSetting(key, def string) string {
	var val string
	if err := h.db.QueryRow("SELECT setting_value FROM settings WHERE setting_name=?", key).Scan(&val); err != nil || val == "" {
		return def
	}
	return val
}
