package database

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
)

// RetiredSettings are settings that nothing reads any more. The settings page
// showed each of them as a control, and none of them changed what the stack
// does:
//   - tailscale_enabled, tailscale_auth_key, tailscale_hostname: Tailscale is
//     a compose profile fed by TS_AUTHKEY in .env. The auth key sat in the
//     database in clear (it was never a sensitive key) and went out in every
//     database export.
//   - ddns_enabled, ddns_provider, ddns_domain, ddns_token: no dynamic DNS
//     client exists in the repository; the token sat in clear as well.
//   - auth_method: the proxy only ever emits auth_param basic.
//   - enable_ip_blacklist, enable_domain_blacklist, enable_waf,
//     block_direct_ip: read only by the security score (removed). Squid
//     always denies the IP and domain blacklists and direct-IP URLs, and the
//     WAF is always on the ICAP path, whatever these said.
//   - allowed_networks: client networks allowed to use the proxy are set by
//     the Squid configuration and GUI_IP_WHITELIST in .env; nothing in the
//     backend or proxy ever read this key from settings.
//   - waf_custom_rules: the WAF loads custom rules from
//     /config/waf_custom_rules.txt; nothing ever read this key from settings.
//   - waf_block_threshold: the WAF uses its compiled anomaly thresholds and
//     the waf_h_* heuristic toggles; nothing ever read this key from settings.
//
// Version 6 deletes the first 12 rows. Version 8 archives any stored value of
// allowed_networks, waf_custom_rules, and waf_block_threshold into audit_log
// (action retire_setting_value) before deleting their rows (#444). The API
// refuses to write any of RetiredSettings again (they are not writable keys)
// and restore skips them with a reason, so an old backup cannot bring them
// back.
var (
	retiredSettingsV6 = []string{
		"tailscale_enabled", "tailscale_auth_key", "tailscale_hostname",
		"ddns_enabled", "ddns_provider", "ddns_domain", "ddns_token",
		"auth_method",
		"enable_ip_blacklist", "enable_domain_blacklist", "enable_waf", "block_direct_ip",
	}

	RetiredSettingsV8 = []string{
		"allowed_networks", "waf_custom_rules", "waf_block_threshold",
	}

	RetiredSettings = append(append([]string(nil), retiredSettingsV6...), RetiredSettingsV8...)
)

const retiredSettingValueMaxBytes = 64 * 1024

// IsRetiredSetting reports whether key is one of RetiredSettings.
func IsRetiredSetting(key string) bool {
	for _, k := range RetiredSettings {
		if k == key {
			return true
		}
	}
	return false
}

// deleteRetiredSettings is schema version 6: the rows of retiredSettingsV6 go,
// in one transaction that records the version.
func deleteRetiredSettings(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	args := make([]any, len(retiredSettingsV6))
	for i, k := range retiredSettingsV6 {
		args[i] = k
	}
	placeholders := Placeholders(len(retiredSettingsV6))
	// #nosec G202 -- placeholders only; the keys are bound
	res, err := tx.Exec(string("DELETE FROM settings WHERE setting_name IN ("+placeholders+")"), args...) // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
	if err != nil {
		return err
	}
	deleted, _ := res.RowsAffected()
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", 6)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Info().Int("version", 6).Int64("rows", deleted).Msg("schema migrated: settings nothing reads were deleted")
	return nil
}

// retireThreeSettings is schema version 8: for each of allowed_networks,
// waf_custom_rules, and waf_block_threshold present in settings, it writes an
// audit_log row (user "system", action "retire_setting_value", target key,
// details {"value": ..., "truncated": true if > 64 KiB}), deletes the rows,
// and records PRAGMA user_version = 8 in one transaction (#444).
func retireThreeSettings(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	args := make([]any, len(RetiredSettingsV8))
	for i, k := range RetiredSettingsV8 {
		args[i] = k
	}
	placeholders := Placeholders(len(RetiredSettingsV8))

	// #nosec G202 -- placeholders only; the keys are bound
	rows, err := tx.Query(
		string("SELECT setting_name, setting_value FROM settings WHERE setting_name IN ("+placeholders+") ORDER BY setting_name"), // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
		args...,
	)
	if err != nil {
		return err
	}
	type pair struct{ name, value string }
	var found []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.name, &p.value); err != nil {
			rows.Close()
			return err
		}
		found = append(found, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, p := range found {
		payload := map[string]any{"value": p.value}
		if len(p.value) > retiredSettingValueMaxBytes {
			payload["value"] = p.value[:retiredSettingValueMaxBytes]
			payload["truncated"] = true
		}
		details, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(
			"INSERT INTO audit_log(username, action, target, details) VALUES('system', 'retire_setting_value', ?, ?)",
			p.name, string(details),
		); err != nil {
			return err
		}
	}

	var deleted int64
	if len(found) > 0 {
		// #nosec G202 -- placeholders only; the keys are bound
		res, err := tx.Exec(string("DELETE FROM settings WHERE setting_name IN ("+placeholders+")"), args...) // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
		if err != nil {
			return err
		}
		deleted, _ = res.RowsAffected()
	}

	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", 8)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Info().Int("version", 8).Int64("rows", deleted).Msg("schema migrated: retired settings archived to audit_log and deleted")
	return nil
}
