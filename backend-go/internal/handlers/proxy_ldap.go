package handlers

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/atomicfile"
	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
)

// Proxy login against an LDAP directory (OpenLDAP, Active Directory): with
// proxy login on and its source set to ldap, the proxy checks each client's
// username and password with Squid's basic_ldap_auth instead of the local
// password file, and, when a group is set, lets in only its members
// (ext_ldap_group_acl). Settings > Clients and access > Login.
const (
	settingProxyAuthSource = "proxy_auth_source"
	settingLDAPURL         = "ldap_url"
	settingLDAPBindDN      = "ldap_bind_dn"
	settingLDAPBindPass    = "ldap_bind_password"
	settingLDAPUserBase    = "ldap_user_base_dn"
	settingLDAPUserFilter  = "ldap_user_filter"
	settingLDAPGroup       = "ldap_group"
	settingLDAPGroupBase   = "ldap_group_base_dn"
	settingLDAPGroupFilter = "ldap_group_filter"

	proxyAuthLocal = "local"
	proxyAuthLDAP  = "ldap"

	// ldapMarkerName in /config tells the generator that the source is LDAP,
	// so a missing or broken LDAP file refuses every client rather than
	// falling back to the local password file. ldapConfName and
	// ldapPasswordName are in the proxy-secrets volume.
	ldapMarkerName   = "proxy_auth_ldap"
	ldapConfName     = "ldap.conf"
	ldapPasswordName = "ldap_bind_password"
)

// What reaches the helpers' command line, each value one argument Squid
// passes as it is (a quoted value keeps its spaces: measured on the proxy
// image). No quote, backslash or # in any of them; the generator checks the
// same patterns again (proxy/generate_squid_conf.sh).
var (
	ldapURLRE    = regexp.MustCompile(`^ldaps?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$`)
	ldapDNRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 =,._@-]{0,511}$`)
	ldapFilterRE = regexp.MustCompile(`^\([A-Za-z0-9=()&|!*%._@-]{1,254}\)$`)
	ldapGroupRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	// The bind password is a file the helper reads (-W), never a command line
	// argument: any printable character but a newline.
	ldapPasswordRE = regexp.MustCompile(`^[ -~]{1,256}$`)
)

func optional(re *regexp.Regexp, why string) func(string) error {
	return func(v string) error {
		if v == "" || re.MatchString(v) {
			return nil
		}
		return errors.New(why)
	}
}

func init() {
	settingValidators[settingProxyAuthSource] = validChoice(proxyAuthLocal, proxyAuthLDAP)
	settingValidators[settingLDAPURL] = optional(ldapURLRE, "ldap://host or ldaps://host, with an optional :port and nothing after it")
	settingValidators[settingLDAPBindDN] = optional(ldapDNRE, "a DN or a user principal name: letters, digits, spaces and = , . _ @ -")
	settingValidators[settingLDAPUserBase] = optional(ldapDNRE, "a DN: letters, digits, spaces and = , . _ @ -")
	settingValidators[settingLDAPGroupBase] = optional(ldapDNRE, "a DN: letters, digits, spaces and = , . _ @ -")
	settingValidators[settingLDAPGroup] = optional(ldapGroupRE, "a group name: letters, digits and . _ -, no space")
	settingValidators[settingLDAPBindPass] = optional(ldapPasswordRE, "printable characters, up to 256")
	settingValidators[settingLDAPUserFilter] = func(v string) error {
		if v == "" {
			return nil
		}
		if !ldapFilterRE.MatchString(v) || !strings.Contains(v, "%s") {
			return errors.New(`an LDAP filter in parentheses with %s for the username, such as (uid=%s) or (sAMAccountName=%s); no space`)
		}
		return nil
	}
	settingValidators[settingLDAPGroupFilter] = func(v string) error {
		if v == "" {
			return nil
		}
		if !ldapFilterRE.MatchString(v) || !strings.Contains(v, "%g") || !strings.Contains(v, "%u") {
			return errors.New(`an LDAP filter in parentheses with %g for the group and %u for the user's DN, such as (&(cn=%g)(member=%u)); no space`)
		}
		return nil
	}
}

// ldapFiles are the proxy's LDAP files as the stored settings make them:
// conf and password, or nil when the source is not LDAP or a required value
// is missing or invalid. Login on with the source LDAP and no files refuses
// every client: the generator never falls back to the local password file.
func (h *SettingsHandlers) ldapFiles() (conf, password []byte) {
	if h.dbSetting(settingProxyAuth, "false") != "true" || h.dbSetting(settingProxyAuthSource, proxyAuthLocal) != proxyAuthLDAP {
		return nil, nil
	}
	url, bindDN, userBase := h.dbSetting(settingLDAPURL, ""), h.dbSetting(settingLDAPBindDN, ""), h.dbSetting(settingLDAPUserBase, "")
	userFilter := h.dbSetting(settingLDAPUserFilter, "(uid=%s)")
	group, groupBase := h.dbSetting(settingLDAPGroup, ""), h.dbSetting(settingLDAPGroupBase, "")
	groupFilter := h.dbSetting(settingLDAPGroupFilter, "(&(cn=%g)(member=%u))")
	if !ldapURLRE.MatchString(url) || !ldapDNRE.MatchString(bindDN) || !ldapDNRE.MatchString(userBase) ||
		settingValidators[settingLDAPUserFilter](userFilter) != nil {
		log.Warn().Msg("proxy login from LDAP is on but its URL, bind DN, user base or user filter is missing or invalid: every client is refused")
		return nil, nil
	}
	stored := h.dbSetting(settingLDAPBindPass, "")
	if stored == "" {
		log.Warn().Msg("proxy login from LDAP is on but no bind password is set: every client is refused")
		return nil, nil
	}
	pass, err := appcrypto.Decrypt(stored, h.cfg.EncryptionKey)
	if err != nil || !ldapPasswordRE.MatchString(pass) {
		log.Warn().Err(err).Msg("the LDAP bind password cannot be decrypted or is not valid: every client is refused")
		return nil, nil
	}
	var b bytes.Buffer
	b.WriteString("LDAP_URL=" + url + "\nLDAP_BIND_DN=" + bindDN + "\nLDAP_USER_BASE=" + userBase + "\nLDAP_USER_FILTER=" + userFilter + "\n")
	if group != "" {
		if !ldapGroupRE.MatchString(group) || !ldapDNRE.MatchString(groupBase) || settingValidators[settingLDAPGroupFilter](groupFilter) != nil {
			log.Warn().Msg("proxy login from LDAP has a group but its base or filter is missing or invalid: every client is refused")
			return nil, nil
		}
		b.WriteString("LDAP_GROUP=" + group + "\nLDAP_GROUP_BASE=" + groupBase + "\nLDAP_GROUP_FILTER=" + groupFilter + "\n")
	}
	return b.Bytes(), []byte(pass)
}

// SyncProxyLDAP brings the proxy's LDAP files in line with the stored
// settings: the marker in /config while the source is LDAP and login is on,
// and the conf and the bind password in the secrets volume while they are
// complete. The password file is root:proxy 0640: the helper runs as the
// proxy user and reads it (-W), so it is never on a command line. It reports
// whether anything changed.
func (h *SettingsHandlers) SyncProxyLDAP() (changed bool, err error) {
	marker := filepath.Join(h.cfg.ConfigDir, ldapMarkerName)
	confPath := filepath.Join(h.cfg.SecretsDir, ldapConfName)
	passPath := filepath.Join(h.cfg.SecretsDir, ldapPasswordName)
	ldapOn := h.dbSetting(settingProxyAuth, "false") == "true" && h.dbSetting(settingProxyAuthSource, proxyAuthLocal) == proxyAuthLDAP

	if c, err := setPresence(marker, ldapOn); err != nil {
		return changed, err
	} else if c {
		changed = true
	}
	conf, pass := h.ldapFiles()
	if conf == nil {
		for _, p := range []string{confPath, passPath} {
			if err := os.Remove(p); err == nil {
				changed = true
			} else if !os.IsNotExist(err) {
				return changed, err
			}
		}
		return changed, nil
	}
	haveConf, confErr := os.ReadFile(confPath) // #nosec G304 -- fixed name in the secrets dir
	if confErr != nil || !bytes.Equal(haveConf, conf) {
		if err := atomicfile.Write(confPath, conf, 0o600); err != nil {
			return changed, err
		}
		changed = true
	}
	havePass, passErr := os.ReadFile(passPath) // #nosec G304 -- fixed name in the secrets dir
	if passErr != nil || !bytes.Equal(havePass, pass) {
		groupSet, err := atomicfile.WriteGroup(passPath, pass, 0o640, proxyGroupID)
		if err != nil {
			return changed, err
		}
		if !groupSet {
			log.Warn().Int("gid", proxyGroupID).Msg("the LDAP bind password file could not be given the proxy group (the backend needs group_add: 13): the proxy's helper cannot read it")
		}
		changed = true
	}
	return changed, nil
}

// setPresence creates (an empty file) or removes path, and reports whether
// it changed.
func setPresence(path string, present bool) (bool, error) {
	_, err := os.Stat(path)
	exists := err == nil
	switch {
	case present && !exists:
		// #nosec G306 -- a marker the proxy reads, no content
		return true, os.WriteFile(path, nil, 0o644)
	case !present && exists:
		return true, os.Remove(path)
	}
	return false, nil
}

// carriesProxyLDAP reports whether a save or restore touches the settings
// the LDAP files follow.
func carriesProxyLDAP(body map[string]string) bool {
	for k := range body {
		if strings.HasPrefix(k, "ldap_") || k == settingProxyAuthSource || k == settingProxyAuth {
			return true
		}
	}
	return false
}

// syncProxyLDAPAndReload runs SyncProxyLDAP for a save or a restore and asks
// the proxy to reload when something changed; it returns the file name when
// it could not write, for the save's list of failed artefacts.
func (h *SettingsHandlers) syncProxyLDAPAndReload() (failed string) {
	changed, err := h.SyncProxyLDAP()
	if err != nil {
		log.Warn().Err(err).Str("dir", h.cfg.SecretsDir).Msg("the proxy's LDAP files could not be written (is the proxy-secrets volume mounted?)")
		return ldapConfName
	}
	if changed {
		if err := requestProxyReload(h.cfg.ConfigDir); err != nil {
			log.Warn().Err(err).Msg("proxy reload trigger not written after the LDAP files changed")
		}
	}
	return ""
}

// SyncProxyLDAPAtStartup is syncProxyLDAPAndReload for the server's start.
func (h *SettingsHandlers) SyncProxyLDAPAtStartup() {
	if failed := h.syncProxyLDAPAndReload(); failed != "" {
		log.Error().Str("file", failed).Msg("startup: the proxy's LDAP files could not be brought in line with the stored settings")
	}
}

// ldapLoginErrors adds to errs what a save that leaves login on with the
// source LDAP lacks: the proxy would refuse every client.
func (h *SettingsHandlers) ldapLoginErrors(errs map[string]string, effective func(string) string, passwordAfterSave bool) {
	const why = ": with proxy login from LDAP on, the proxy refuses every client without it"
	for k, what := range map[string]string{
		settingLDAPURL: "set the directory's URL", settingLDAPBindDN: "set the account the proxy searches with",
		settingLDAPUserBase: "set where users are searched",
	} {
		if errs[k] == "" && effective(k) == "" {
			errs[k] = what + why
		}
	}
	if errs[settingLDAPBindPass] == "" && !passwordAfterSave {
		errs[settingLDAPBindPass] = "set the search account's password" + why
	}
	if effective(settingLDAPGroup) != "" && errs[settingLDAPGroupBase] == "" && effective(settingLDAPGroupBase) == "" {
		errs[settingLDAPGroupBase] = "set where groups are searched, or clear the group"
	}
}
