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

// The upstream (parent) proxy: Squid forwards the clients' requests to
// another proxy instead of the destinations, as in a network where a
// corporate proxy is the only way out. Settings > Proxy engine. Every request
// goes through it except those to the domains listed to go direct; while it
// is down, requests fail. A mode that went direct when the parent was down
// was tried and measured wrong (HTTPS went direct with the parent up, and the
// parent was not used again after an outage), so there is none.
const (
	settingUpstreamEnabled  = "upstream_proxy_enabled"
	settingUpstreamHost     = "upstream_proxy_host"
	settingUpstreamPort     = "upstream_proxy_port"
	settingUpstreamUsername = "upstream_proxy_username"
	settingUpstreamPassword = "upstream_proxy_password"
	settingUpstreamDirect   = "upstream_proxy_direct_domains"

	// upstreamConfName is in the proxy-secrets volume (cfg.SecretsDir): it
	// holds the parent's password in clear, as Squid's cache_peer login=
	// needs it. upstreamDirectName is in /config: it is not secret.
	upstreamConfName   = "upstream_proxy.conf"
	upstreamDirectName = "upstream_direct_domains.txt"
)

// The login reaches squid.conf as cache_peer login=user:password, one token
// of a line Squid splits on white space: no space, quote, backslash or
// comment sign, and no "%", which Squid may read as an escape. The generator
// (proxy/generate_squid_conf.sh) checks the same patterns again.
var (
	upstreamUserRE     = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	upstreamPasswordRE = regexp.MustCompile(`^[A-Za-z0-9!$&()*+,./:;<=>?@^_{|}~-]{1,128}$`)
)

func init() {
	settingValidators[settingUpstreamHost] = validHostOrEmpty
	settingValidators[settingUpstreamPort] = validPort
	settingValidators[settingUpstreamDirect] = validDomainList
	settingValidators[settingUpstreamUsername] = func(v string) error {
		if v == "" || upstreamUserRE.MatchString(v) {
			return nil
		}
		return errors.New("1 to 64 letters, digits, dots, hyphens, underscores or @")
	}
	settingValidators[settingUpstreamPassword] = func(v string) error {
		if v == "" || upstreamPasswordRE.MatchString(v) {
			return nil
		}
		return errors.New(`1 to 128 characters: letters, digits and ! $ & ( ) * + , . / : ; < = > ? @ ^ _ { | } ~ - (no space, quote, backslash, # or %, which the proxy's configuration cannot carry)`)
	}
}

// validHostOrEmpty is empty, an IP address, or a DNS name.
func validHostOrEmpty(v string) error { return validLogForwardHost(v) }

// upstreamConf is what the generator reads, or nil when no upstream proxy
// is in force: switched off, no host, or a stored value that fails its rule.
// A password that cannot be decrypted (the key changed) drops the login and
// is reported; the parent then refuses the requests, which says why.
func (h *SettingsHandlers) upstreamConf() []byte {
	if h.dbSetting(settingUpstreamEnabled, "false") != "true" {
		return nil
	}
	host := h.dbSetting(settingUpstreamHost, "")
	port := h.dbSetting(settingUpstreamPort, "3128")
	if host == "" || validHostOrEmpty(host) != nil || validPort(port) != nil {
		log.Warn().Msg("upstream proxy is on but its host or port is missing or invalid: not written")
		return nil
	}
	var b bytes.Buffer
	b.WriteString("UPSTREAM_HOST=" + host + "\nUPSTREAM_PORT=" + port + "\n")
	user := h.dbSetting(settingUpstreamUsername, "")
	if stored := h.dbSetting(settingUpstreamPassword, ""); stored != "" && user != "" {
		password, err := appcrypto.Decrypt(stored, h.cfg.EncryptionKey)
		switch {
		case err != nil:
			log.Warn().Err(err).Msg("the upstream proxy password cannot be decrypted: written without a login")
		case !upstreamUserRE.MatchString(user) || !upstreamPasswordRE.MatchString(password):
			log.Warn().Msg("the stored upstream proxy login does not fit the proxy's configuration: written without a login")
		default:
			b.WriteString("UPSTREAM_USER=" + user + "\nUPSTREAM_PASSWORD=" + password + "\n")
		}
	}
	return b.Bytes()
}

// SyncUpstreamProxy brings the proxy's upstream files in line with the stored
// settings: upstream_proxy.conf in the secrets volume (removed when no upstream
// proxy is in force) and the domains that go direct in /config. It reports
// whether the conf changed. It runs after a save or a restore that touches
// the settings, and at startup.
func (h *SettingsHandlers) SyncUpstreamProxy() (changed bool, err error) {
	if err := h.writeListArtefact(upstreamDirectName, h.dbSetting(settingUpstreamDirect, ""), cacheBypassEntry); err != nil {
		return false, err
	}
	path := filepath.Join(h.cfg.SecretsDir, upstreamConfName)
	want := h.upstreamConf()
	have, readErr := os.ReadFile(path) // #nosec G304 -- fixed name in the secrets dir
	if want == nil {
		if readErr != nil {
			return false, nil
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		return true, nil
	}
	if readErr == nil && bytes.Equal(have, want) {
		return false, nil
	}
	if err := atomicfile.Write(path, want, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// carriesUpstream reports whether a save or restore body touches the
// upstream proxy settings.
func carriesUpstream(body map[string]string) bool {
	for k := range body {
		if strings.HasPrefix(k, "upstream_proxy_") {
			return true
		}
	}
	return false
}

// syncUpstreamProxy runs SyncUpstreamProxy for a save or a restore; it
// returns the file name when it could not be written, for the save's list of
// failed artefacts. The page reloads the proxy after a save of these settings.
func (h *SettingsHandlers) syncUpstreamProxy() (failed string) {
	if _, err := h.SyncUpstreamProxy(); err != nil {
		log.Warn().Err(err).Str("dir", h.cfg.SecretsDir).Msg("the upstream proxy files could not be written (is the proxy-secrets volume mounted?)")
		return upstreamConfName
	}
	return ""
}

// SyncUpstreamProxyAtStartup is SyncUpstreamProxy for the server's start: a
// change asks the proxy to reload.
func (h *SettingsHandlers) SyncUpstreamProxyAtStartup() {
	changed, err := h.SyncUpstreamProxy()
	if err != nil {
		log.Error().Err(err).Str("dir", h.cfg.SecretsDir).Msg("startup: the upstream proxy files could not be written (is the proxy-secrets volume mounted?)")
		return
	}
	if changed {
		if err := requestProxyReload(h.cfg.ConfigDir); err != nil {
			log.Warn().Err(err).Msg("proxy reload trigger not written after the upstream proxy file changed")
		}
	}
}
