package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
	appMW "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/rs/zerolog/log"
)

// validateBody checks every value a save carries and returns every problem,
// by key, with the message the settings page shows under that field. Values
// that depend on each other are checked together, with the stored value for
// the half the request does not carry: the window must end after it starts,
// and content filtering needs at least one extension. A check that involves
// none of the request's keys is not run, so a stored problem in one section
// does not block saving another. clearKeys are the secrets the request
// removes (?clear=); an empty secret that is not among them keeps its value.
func (h *SettingsHandlers) validateBody(body map[string]string, clearKeys map[string]bool) map[string]string {
	errs := map[string]string{}
	for k, v := range body {
		if !isWritableSettingKey(k) || len(v) > 10000 {
			continue // skipped by persistSettings, as before
		}
		if appcrypto.IsSensitive(k) && v == "" {
			continue // an untouched secret keeps its stored value
		}
		if err := validateSettingValue(k, v); err != nil {
			errs[k] = strings.TrimPrefix(err.Error(), k+": ")
		}
	}
	effective := func(k string) string {
		if v, ok := body[k]; ok {
			return v
		}
		return h.dbSetting(k, "")
	}
	carries := func(keys ...string) bool {
		for _, k := range keys {
			if _, ok := body[k]; ok {
				return true
			}
		}
		return false
	}

	// Squid's time ACL needs the window to end after it starts on the same day;
	// 18:00 to 08:00 was saved and written out.
	if carries("enable_time_restrictions", "time_restriction_start", "time_restriction_end") &&
		effective("enable_time_restrictions") == "true" && errs["time_restriction_end"] == "" && errs["time_restriction_start"] == "" {
		start, end := effective("time_restriction_start"), effective("time_restriction_end")
		if timeOfDayRE.MatchString(start) && timeOfDayRE.MatchString(end) && end <= start {
			errs["time_restriction_end"] = "must be later than the start time"
		}
	}
	// With no extension the generator leaves the rule out: the switch reads
	// on and nothing is blocked.
	if carries("enable_content_filtering", "blocked_file_types") &&
		effective("enable_content_filtering") == "true" && errs["blocked_file_types"] == "" &&
		len(listItems(effective("blocked_file_types"))) == 0 {
		errs["blocked_file_types"] = "list at least one extension: with an empty list the proxy blocks nothing"
	}
	// With login on and no credentials the proxy refuses every client
	// (generate_squid_conf.sh fails closed), so login cannot be turned on, or
	// its credentials removed, without the other half.
	if carriesProxyLogin(body, clearKeys) && effective(settingProxyAuth) == "true" {
		const why = ": with proxy login on and no credentials the proxy refuses every client"
		if errs[settingProxyUsername] == "" && effective(settingProxyUsername) == "" {
			errs[settingProxyUsername] = "set the username devices sign in with" + why
		}
		if errs[settingProxyPassword] == "" && !h.proxyPasswordAfterSave(body, clearKeys) {
			errs[settingProxyPassword] = "set the password devices sign in with" + why
		}
	}
	return errs
}

// proxyPasswordAfterSave reports whether a proxy password will be stored
// once the request is saved: a typed one, or the stored one kept.
func (h *SettingsHandlers) proxyPasswordAfterSave(body map[string]string, clearKeys map[string]bool) bool {
	if clearKeys[settingProxyPassword] {
		return false
	}
	if body[settingProxyPassword] != "" {
		return true
	}
	return h.dbSetting(settingProxyPassword, "") != ""
}

// writeFieldErrors answers 400 with every refused field in errors and, for a
// caller that reads only detail, the first of them as "<key>: <message>"
// (the shape detail always had).
func writeFieldErrors(w http.ResponseWriter, errs map[string]string) {
	keys := make([]string, 0, len(errs))
	for k := range errs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"status": "error",
		"detail": keys[0] + ": " + errs[keys[0]],
		"errors": errs,
	})
}

// wafPushResult is what the running WAF did with the heuristic toggles of a
// save.
type wafPushResult struct {
	Pushed []string        `json:"pushed"`
	Failed []wafPushFailed `json:"failed"`
}

type wafPushFailed struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// heuristicSettingKeys are the WAF heuristic toggles that must be propagated to
// the running WAF, which otherwise only reads WAF_H_* env at startup. Keep in
// sync with the WAF's heuristicToggles map (waf-go/internal/engine/heuristics.go).
var heuristicSettingKeys = map[string]bool{
	"waf_h_entropy":   true,
	"waf_h_beaconing": true,
	"waf_h_pii":       true,
	"waf_h_sharding":  true,
	"waf_h_ghosting":  true,
	"waf_h_sequence":  true,
}

// wafRefusal says why the WAF did not take a management call.
func wafRefusal(alertToken string, err error, status int) string {
	switch {
	case errors.Is(err, appMW.ErrCircuitOpen):
		return "the WAF failed several calls in a row, so the backend is not calling it for a few seconds"
	case err != nil:
		return "the WAF could not be reached"
	case (status == http.StatusForbidden || status == http.StatusUnauthorized) && alertToken == "":
		return "INTERNAL_ALERT_TOKEN is not set, and the WAF refuses management calls without it: set it to the same value on the waf and backend services"
	case status == http.StatusForbidden || status == http.StatusUnauthorized:
		return fmt.Sprintf("the WAF refused the backend's credential (HTTP %d): INTERNAL_ALERT_TOKEN must be the same on the waf and backend services", status)
	default:
		return fmt.Sprintf("the WAF answered HTTP %d", status)
	}
}

// pushHeuristicsToWAF propagates the heuristic toggles in the just-saved
// settings to the WAF's runtime config (POST /heuristics/toggle) and returns
// what it answered for each, or nil when the save carried none. The database
// stays authoritative: a refused push does not fail the save, and
// workers.StartWAFReconciler pushes the stored values again every 30 seconds
// until the WAF matches.
//
// The value "still applies on the WAF's next restart via WAF_H_* env" was
// claimed here once; it does not: those variables come from the compose file
// and never carry the stored value (SECURE-CONF-02).
func (h *SettingsHandlers) pushHeuristicsToWAF(ctx context.Context, body map[string]string) *wafPushResult {
	keys := make([]string, 0, len(heuristicSettingKeys))
	for key := range body {
		if heuristicSettingKeys[key] {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	res := &wafPushResult{Pushed: []string{}, Failed: []wafPushFailed{}}
	for _, key := range keys {
		payload, err := json.Marshal(map[string]any{"heuristic": key, "enabled": body[key] == "true"})
		if err != nil {
			continue
		}
		resp, err := wafPostBreaker(ctx, h.cfg, "/heuristics/toggle", bytes.NewReader(payload))
		status := 0
		if err == nil {
			status = resp.StatusCode
			resp.Body.Close() //nolint:errcheck
		}
		if err == nil && status == http.StatusOK {
			res.Pushed = append(res.Pushed, key)
			continue
		}
		reason := wafRefusal(h.cfg.AlertToken, err, status)
		log.Warn().Str("key", key).Int("status", status).Str("reason", reason).Msg("heuristic toggle not applied to the WAF")
		res.Failed = append(res.Failed, wafPushFailed{Key: key, Reason: reason})
	}
	return res
}

// WAFHeuristics reports which heuristics the running WAF applies (its GET
// /heuristics), so the settings page can show the effective state next to the
// stored one. When the WAF cannot be asked, available is false and reason
// says why.
func (h *SettingsHandlers) WAFHeuristics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	resp, err := wafGetBreaker(ctx, h.cfg, "/heuristics")
	if err != nil {
		writeOK(w, map[string]any{"available": false, "reason": wafRefusal(h.cfg.AlertToken, err, 0)})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeOK(w, map[string]any{"available": false, "reason": wafRefusal(h.cfg.AlertToken, nil, resp.StatusCode)})
		return
	}
	var body struct {
		Data map[string]bool `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Data == nil {
		writeOK(w, map[string]any{"available": false, "reason": "the WAF's answer could not be read"})
		return
	}
	running := map[string]bool{}
	for k, v := range body.Data {
		if heuristicSettingKeys[k] {
			running[k] = v
		}
	}
	writeOK(w, map[string]any{"available": true, "running": running})
}

// listArtefacts are the /config files that are a pure function of one
// setting: the proxy reads the file, the database holds the setting. The
// transforms are the save path's own, so a start never rewrites a file in
// another form than a save does (a copy here still wrote "\.exe$", and every
// restart reopened the query-string bypass).
var listArtefacts = []struct {
	key, file string
	transform func(string) string
}{
	{"blocked_file_types", "blocked_file_types.txt", blockedExtensionPattern},
	{"cache_bypass_domains", "cache_bypass_domains.txt", cacheBypassEntry},
}

// listArtefactContent is the file content writeListArtefact writes for value.
func listArtefactContent(value string, transform func(string) string) string {
	var items []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(strings.ToLower(item))
		if item != "" {
			items = append(items, transform(item))
		}
	}
	if len(items) == 0 {
		return ""
	}
	return strings.Join(items, "\n") + "\n"
}

// SyncListArtefacts writes each list file whose content differs from the
// stored setting, at startup, and asks the proxy to reload when one changed.
// The files were written only by a save, so a value the database gained any
// other way (a seeded default, a restore from an older version) was shown on
// the settings page while the proxy enforced the file as it was, or no file
// at all. A setting with no stored row leaves its file alone.
func (h *SettingsHandlers) SyncListArtefacts() (changed []string) {
	for _, a := range listArtefacts {
		var value string
		if err := h.db.QueryRow("SELECT setting_value FROM settings WHERE setting_name=?", a.key).Scan(&value); err != nil {
			continue
		}
		path := filepath.Join(h.cfg.ConfigDir, a.file)
		want := listArtefactContent(value, a.transform)
		// #nosec G304 -- fixed file names under the config directory
		have, err := os.ReadFile(path)
		if err == nil && string(have) == want {
			continue
		}
		if err != nil && want == "" {
			continue // no file and nothing to write
		}
		if err := h.writeListArtefact(a.file, value, a.transform); err != nil {
			log.Warn().Str("file", a.file).Err(err).Msg("startup: list file not written")
			continue
		}
		changed = append(changed, a.file)
	}
	if len(changed) > 0 {
		if err := requestProxyReload(h.cfg.ConfigDir); err != nil {
			log.Warn().Err(err).Msg("startup: proxy reload trigger not written")
		}
		log.Info().Strs("files", changed).Msg("startup: list files brought in line with the stored settings")
	}
	return changed
}
