package database

import (
	"database/sql"
	"fmt"
	"strings"

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
//
// Version 5 deletes their rows. The API refuses to write them again (they are
// not writable keys) and restore skips them with a reason, so an old backup
// cannot bring the clear-text tokens back.
var RetiredSettings = []string{
	"tailscale_enabled", "tailscale_auth_key", "tailscale_hostname",
	"ddns_enabled", "ddns_provider", "ddns_domain", "ddns_token",
	"auth_method",
	"enable_ip_blacklist", "enable_domain_blacklist", "enable_waf", "block_direct_ip",
}

// IsRetiredSetting reports whether key is one of RetiredSettings.
func IsRetiredSetting(key string) bool {
	for _, k := range RetiredSettings {
		if k == key {
			return true
		}
	}
	return false
}

// deleteRetiredSettings is schema version 6: the rows of RetiredSettings go,
// in one transaction that records the version.
func deleteRetiredSettings(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	args := make([]any, len(RetiredSettings))
	for i, k := range RetiredSettings {
		args[i] = k
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(RetiredSettings)), ",")
	// #nosec G202 -- placeholders only; the keys are bound
	res, err := tx.Exec("DELETE FROM settings WHERE setting_name IN ("+placeholders+")", args...)
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
