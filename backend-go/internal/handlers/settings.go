package handlers

import (
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
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/netguard"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/privacy"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

// settingValidators gives the values a server-side domain. The table was
// TEXT-to-TEXT with no per-key validation, so the only shape checking for
// ports, emails and booleans was a zod schema running in the BROWSER — bypassed
// by any direct API call. proxy_port='abc' was persisted and then written into
// the file Squid's config generator sources (SECURE-DOM-06).
var settingValidators = map[string]func(string) error{
	"proxy_port": validPort,
	// The proxy's generator reads at most 7 digits for the disk cache and 6
	// for memory and silently keeps its default for anything longer
	// (generate_squid_conf.sh), so a longer value was saved and never used.
	"cache_size":           validMegabytes(7),
	"memory_cache":         validMegabytes(6),
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
	// The refresh worker reads anything that is not a number as 0 and then
	// never refreshes.
	"auto_refresh_hours":            validRefreshHours,
	"egress_provider_refresh_hours": validBoundedInt(6, 168, "hours"),
	// Each entry becomes the urlpath_regex \.<entry>$; "*" became \.*$, which
	// matches every path, and nothing checked it.
	"blocked_file_types": validExtensionList,
	// Each entry becomes a dstdomain line in a file Squid loads.
	"cache_bypass_domains": validDomainList,
	// Alert destinations the backend posts to (netguard.CheckNotifyURL).
	"webhook_url":       validNotifyURL,
	"gotify_url":        validNotifyURL,
	"teams_webhook_url": validNotifyURL,
	"ntfy_url":          validNotifyURL,
	// The notification limits (notify_limit.go). A value out of range is read
	// as the default, so it is refused here rather than saved and ignored.
	settingGroupWindow:        validBoundedInt(1, maxGroupWindowMinutes, "minutes"),
	settingMaxPerHour:         validBoundedInt(1, maxMaxPerHour, "alerts"),
	settingNotifyWAFBlock:     validBool,
	settingNotifyLoginFailure: validBool,
	settingMinLevel:           validAlertLevel,
	// The proxy login (proxy_login.go). Both end up in proxy_users.htpasswd,
	// one line of "username:hash" that Squid's helper reads.
	settingProxyUsername: validProxyUsername,
	settingProxyPassword: validProxyPassword,
}

// validBoundedInt accepts a whole number from lo to hi.
func validBoundedInt(lo, hi int, unit string) func(string) error {
	return func(v string) error {
		if _, ok := parseBoundedInt(v, lo, hi); !ok {
			return fmt.Errorf("must be a whole number of %s, from %d to %d", unit, lo, hi)
		}
		return nil
	}
}

func validBool(v string) error {
	if v != "true" && v != "false" {
		return fmt.Errorf("must be true or false")
	}
	return nil
}

func validAlertLevel(v string) error {
	if _, ok := alertLevels[v]; !ok {
		return fmt.Errorf("must be info, warning or error")
	}
	return nil
}

func validMegabytes(digits int) func(string) error {
	max := 1
	for i := 0; i < digits; i++ {
		max *= 10
	}
	max--
	return func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || len(v) > digits || n < 1 || !digitsRE.MatchString(v) {
			return fmt.Errorf("must be a whole number of megabytes, from 1 to %d", max)
		}
		return nil
	}
}

var digitsRE = regexp.MustCompile(`^[0-9]+$`)

func validRefreshHours(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil || !digitsRE.MatchString(v) || n < 1 || n > 168 {
		return fmt.Errorf("must be a whole number of hours, from 1 to 168")
	}
	return nil
}

// extensionRE is one file extension as the blocked_file_types list holds it.
var extensionRE = regexp.MustCompile(`^\.?[a-zA-Z0-9]{1,10}$`)

// listItems splits a comma-separated setting into its non-empty items.
func listItems(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func validExtensionList(v string) error {
	for _, ext := range listItems(v) {
		if !extensionRE.MatchString(ext) {
			return fmt.Errorf("%q is not a file extension: use letters and digits only, such as exe", ext)
		}
	}
	return nil
}

func validDomainList(v string) error {
	for _, d := range listItems(v) {
		if !isValidDomainEntry(strings.ToLower(d)) {
			return fmt.Errorf("%q is not a domain name, such as bank.example.com", d)
		}
	}
	return nil
}

func validNotifyURL(v string) error {
	if v == "" {
		return nil
	}
	return netguard.CheckNotifyURL(v)
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
// without an entry are free-form text, bounded only by length. A secret that
// is already encrypted (a restored backup carries the enc:: column as it was)
// cannot be inspected and is accepted as it is.
func validateSettingValue(key, value string) error {
	if appcrypto.IsSensitive(key) && appcrypto.IsEncrypted(value) {
		return nil
	}
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
	r.With(authMW).Get("/api/waf/heuristics", h.WAFHeuristics)
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

// Update sets one setting. It goes through the same path as BulkUpdate:
// validation, the write-only handling of secrets, and the artefacts that make
// the setting take effect. It used to write the database row only, so a
// toggle set this way (egress_default_deny, ssl_bump_enabled, ...) never
// reached the marker file the proxy reads, and the API answered success for a
// setting that was not applied.
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
	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Value) > 10000 {
		writeError(w, http.StatusBadRequest, "value too long")
		return
	}
	body := map[string]string{name: req.Value}
	// One key named explicitly with an empty value is a request to clear it,
	// as this route always did; BulkUpdate keeps an empty secret unless clear
	// names it, because a form sends untouched secrets empty.
	clearKeys := map[string]bool{}
	if appcrypto.IsSensitive(name) && req.Value == "" {
		clearKeys[name] = true
	}
	if errs := h.validateBody(body, clearKeys); len(errs) > 0 {
		// A refusal of the value itself keeps its plain detail. The proxy
		// login check can refuse a key the request did not carry (login on
		// with no password stored): those are named in errors.
		if msg, ok := errs[name]; ok && len(errs) == 1 {
			writeError(w, http.StatusBadRequest, msg)
		} else {
			writeFieldErrors(w, errs)
		}
		return
	}
	if _, status, msg := h.persistSettings(body, clearKeys); status != 0 {
		writeError(w, status, msg)
		return
	}
	if user, ok := r.Context().Value(middleware.CtxUsername).(string); ok {
		database.Audit(h.db, user, "update_setting", name, "")
	}
	data := map[string]any{}
	if waf := h.pushHeuristicsToWAF(r.Context(), body); waf != nil {
		data["waf"] = waf
	}
	if failed := h.writeSquidArtefacts(body); len(failed) > 0 {
		data["failed"] = failed
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "partial",
			"message": "setting saved, but some proxy configuration files could not be written",
			"data":    data,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "message": "Setting updated", "data": data})
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

	// Every refused value at once, before anything is written: the first one
	// found used to be the only one reported, in map order, so a section with
	// two bad fields took two round trips to learn about the second.
	if errs := h.validateBody(body, clearKeys); len(errs) > 0 {
		writeFieldErrors(w, errs)
		return
	}

	kept, status, msg := h.persistSettings(body, clearKeys)
	if status != 0 {
		writeError(w, status, msg)
		return
	}

	// Push heuristic toggles to the running WAF so they take effect immediately:
	// the WAF otherwise only reads WAF_H_* env at startup (issue #102). What the
	// WAF answered goes back to the caller, which used to be told "Settings
	// updated" while the WAF refused every toggle for want of
	// INTERNAL_ALERT_TOKEN.
	waf := h.pushHeuristicsToWAF(r.Context(), body)
	data := map[string]any{"kept": kept}
	if waf != nil {
		data["waf"] = waf
	}

	// The handler reads as settings persistence and is in fact a fan-out: after
	// the transaction it writes six configuration artefacts and makes an
	// outbound call to the WAF. Every one of those writes used to be discarded,
	// so a full disk or a read-only /config produced a 200 while the artefacts
	// that make the settings take effect did not exist (SECURE-QUAL-03).
	if failedArtifacts := h.writeSquidArtefacts(body); len(failedArtifacts) > 0 {
		data["failed"] = failedArtifacts
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "partial",
			"message": "settings saved, but some proxy configuration files could not be written",
			"data":    data,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": "Settings updated",
		"data":    data,
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
			enc, err := appcrypto.Encrypt(val, h.cfg.EncryptionKey)
			if err != nil {
				// Refuse rather than store the secret in clear, as Update does
				// (SECURE-ERR-04). This path kept the plaintext and answered 200.
				log.Error().Str("key", k).Err(err).Msg("refusing to store sensitive setting: encryption failed")
				return kept, http.StatusInternalServerError, "encryption unavailable: " + k + " not saved"
			}
			val = enc
		}
		if _, err := tx.Exec(
			"INSERT INTO settings(setting_name,setting_value) VALUES(?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value=excluded.setting_value",
			k, val,
		); err != nil {
			log.Error().Str("key", k).Err(err).Msg("BulkUpdate: failed to save setting, rolling back")
			return kept, http.StatusInternalServerError, "failed to save settings (rolled back)"
		}
	}
	if err := tx.Commit(); err != nil {
		return kept, http.StatusInternalServerError, "failed to commit settings"
	}
	if _, ok := body["gdpr_mode"]; ok {
		privacy.InvalidateDB(h.db)
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
		if err := h.writeListArtefact("cache_bypass_domains.txt", v, cacheBypassEntry); err != nil {
			log.Warn().Err(err).Msg("cache bypass list write failed")
			failedArtifacts = append(failedArtifacts, "cache_bypass_domains.txt")
		}
	}

	// Blocked file types: Squid matches a urlpath_regex ACL, so each extension
	// becomes an anchored pattern.
	if v, ok := body["blocked_file_types"]; ok {
		if err := h.writeListArtefact("blocked_file_types.txt", v, blockedExtensionPattern); err != nil {
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
		log.Warn().Err(err).Msg("squid_settings.env write failed; proxy restart will use previous values")
		failedArtifacts = append(failedArtifacts, "squid_settings.env")
	}

	// The proxy password file, last: it follows the stored settings, which
	// the toggle marker above is part of, and a change to it asks the proxy
	// to reload. A cleared secret is in body with an empty value.
	if carriesProxyLogin(body, nil) {
		if failed := h.syncProxyUsersAndReload(); failed != "" {
			failedArtifacts = append(failedArtifacts, failed)
		}
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

// blockedExtensionPattern is the urlpath_regex line for one blocked file
// extension. Squid matches urlpath_regex against the path WITH its query
// string, so "\.exe$" let /setup.exe?dl=1 through (measured in
// squid_acl_matrix_test.sh). The query is optional and starts at the first
// "?", so /setup.exe.txt?y=1 still does not match. Case is ignored by the
// ACL itself (-i in generate_squid_conf.sh).
func blockedExtensionPattern(ext string) string {
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return `\` + ext + `(\?.*)?$`
}

// cacheBypassEntry is the dstdomain line for one cache-bypass domain: the
// leading dot covers its subdomains.
func cacheBypassEntry(d string) string {
	return "." + strings.TrimPrefix(d, ".")
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

// writeSquidSettingsEnv writes a shell-sourceable env file to /config/squid_settings.env
// so that startup.sh can apply proxy_port, cache_size, memory_cache on container restart.
func (h *SettingsHandlers) writeSquidSettingsEnv(body map[string]string) error {
	port := h.dbSetting("proxy_port", "3128")
	if v, ok := body["proxy_port"]; ok && v != "" {
		port = v
	}
	cache := h.dbSetting("cache_size", database.DefaultCacheSizeMB)
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
		return fmt.Errorf("invalid proxy settings in the database; squid_settings.env not written")
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
		log.Warn().Str("start", start).Str("end", end).Msg("invalid time restriction values, not written")
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
		log.Warn().Msg("invalid bandwidth limit values in the database; bandwidth_limits.conf not written")
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
