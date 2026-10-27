package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/atomicfile"
	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// Proxy login: the username and password devices sign in to the proxy with
// (Settings, Clients and access, Login), and the password file Squid's
// basic_ncsa_auth checks them against. They are their own credentials, not
// the dashboard login: the admin password never leaves the backend.
//
// The file is a pure function of three settings. With enable_proxy_auth on and
// both credentials stored it holds one line, the username and a bcrypt hash of
// the password; otherwise the backend removes a file it wrote. The proxy's
// generator then either requires the login or, with login on and no usable
// file, refuses every client (proxy/generate_squid_conf.sh).
const (
	proxyUsersFileName      = "proxy_users.htpasswd"
	proxyAuthStatusFileName = "proxy_auth_status.json"

	settingProxyAuth     = "enable_proxy_auth"
	settingProxyUsername = "proxy_auth_username"
	settingProxyPassword = "proxy_auth_password"

	// proxyUsersMarker is the first line of a file this backend wrote. A file
	// without it was written by someone else (an operator who passes
	// BASIC_AUTH_* to the proxy container, and its generator, which creates
	// the file from them): the backend replaces it only with credentials of
	// its own and never removes it. basic_ncsa_auth skips lines that start
	// with "#" (measured on the proxy image: "ERR No such user" for "#").
	proxyUsersMarker = "# Written by the Secure Proxy Manager backend from Settings, Clients and access, Login. A save replaces it."

	// proxyUsersPerm lets the proxy's helper, which runs as the proxy user,
	// read the file through its group (proxyGroupID). The generator sets
	// root:proxy 0640 on every run, and the backend writes the same.
	proxyUsersPerm = 0o640

	// Bcrypt reads at most 72 bytes of a password.
	proxyPasswordMaxBytes = 72
	proxyPasswordMinChars = 12
)

// proxyLoginKeys are the settings the password file is derived from.
var proxyLoginKeys = []string{settingProxyAuth, settingProxyUsername, settingProxyPassword}

func carriesProxyLogin(body map[string]string, clearKeys map[string]bool) bool {
	for _, k := range proxyLoginKeys {
		if _, ok := body[k]; ok || clearKeys[k] {
			return true
		}
	}
	return false
}

// proxyUsernameRE is what a proxy username may hold. A colon ends the user
// name in both Basic auth (RFC 7617) and the password file, a newline would
// start a second line in the file, and a space ends the user name in the
// line Squid sends its helper.
var proxyUsernameRE = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,64}$`)

// validProxyUsername accepts an empty value: "not set". Whether one is needed
// is the cross-field check in validateBody.
func validProxyUsername(v string) error {
	if v == "" || proxyUsernameRE.MatchString(v) {
		return nil
	}
	return fmt.Errorf("must be 1 to 64 letters, digits or the characters . _ @ + -, with no spaces or colons")
}

// validProxyPassword accepts an empty value, as validProxyUsername does. A
// stored password is never empty: an empty one in a save keeps the stored
// value, and only ?clear= removes it.
func validProxyPassword(v string) error {
	switch {
	case v == "":
		return nil
	case strings.ContainsAny(v, "\r\n\x00"):
		return fmt.Errorf("must be on one line")
	case utf8.RuneCountInString(v) < proxyPasswordMinChars:
		return fmt.Errorf("must be at least %d characters", proxyPasswordMinChars)
	case len(v) > proxyPasswordMaxBytes:
		return fmt.Errorf("must be at most %d bytes: the proxy's password hash reads no further", proxyPasswordMaxBytes)
	}
	return nil
}

// proxyUsersContent is the file for one user: the marker and the user's line.
func proxyUsersContent(user, password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return []byte(proxyUsersMarker + "\n" + user + ":" + string(hash) + "\n"), nil
}

// proxyUsersManaged reports whether data is a file this backend wrote.
func proxyUsersManaged(data []byte) bool {
	first, _, _ := bytes.Cut(data, []byte("\n"))
	return string(first) == proxyUsersMarker
}

// proxyUsersMatch reports whether data is a file this backend wrote for user
// and password: the marker, then one line for that user whose hash verifies.
func proxyUsersMatch(data []byte, user, password string) bool {
	if !proxyUsersManaged(data) {
		return false
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		return false
	}
	name, hash, ok := strings.Cut(lines[1], ":")
	return ok && name == user && bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// proxyGroupID is the gid of the proxy user in the proxy image (Debian's
// fixed "proxy" user, uid and gid 13), whose basic_ncsa_auth helper reads the
// password file. Both compose files add it to the backend (group_add), which
// runs with no capabilities: a file's owner may give it a group it is a member
// of without CAP_CHOWN. tests/shell/squid_acl_matrix_test.sh checks the image
// still has it and scripts/check-config-contract.sh checks the compose files.
// A variable, not a constant, so a test can stand in a group of its own.
var proxyGroupID = 13

// writeProxyUsersFile replaces path atomically with a file of the proxy
// group, set before the rename, so the proxy's helper reads the new
// credentials at once, also on the file's first write.
//
// A backend outside the proxy group (a compose file without group_add) cannot
// set it: the file then has the backend's group until the proxy's generator
// sets root:proxy, which it does before Squid reloads, and the reload the
// backend requests right after this write bounds that gap. While it lasts
// Squid answers 407 to a credential it has not cached (measured on the proxy
// image: the helper exits on a file it cannot open, Squid restarts it and
// keeps running).
func writeProxyUsersFile(path string, data []byte) error {
	groupSet, err := atomicfile.WriteGroup(path, data, proxyUsersPerm, proxyGroupID)
	if err != nil {
		return err
	}
	if !groupSet {
		log.Warn().Int("gid", proxyGroupID).Str("file", proxyUsersFileName).
			Msg("the proxy password file could not be given the proxy group (the backend needs group_add: 13): the proxy answers 407 to the new credentials until it reloads")
	}
	return nil
}

// SyncProxyUsers brings the password file in line with the stored proxy
// login settings and reports whether it changed the file. It runs after a
// save or a restore that touches them and at startup, so a value the
// database gained any other way reaches the proxy too.
//
// A stored password the backend cannot decrypt (the encryption key changed)
// leaves the file as it is: it still holds the hash of the password the
// operator set, and the settings page asks for the password again.
func (h *SettingsHandlers) SyncProxyUsers() (changed bool, err error) {
	path := filepath.Join(h.cfg.ConfigDir, proxyUsersFileName)
	on := h.dbSetting(settingProxyAuth, "false") == "true"
	user := h.dbSetting(settingProxyUsername, "")
	password := ""
	if stored := h.dbSetting(settingProxyPassword, ""); stored != "" {
		dec, decErr := appcrypto.Decrypt(stored, h.cfg.EncryptionKey)
		if decErr != nil {
			log.Warn().Err(decErr).Msg("the proxy login password cannot be decrypted: the proxy password file is left as it is")
			return false, nil
		}
		password = dec
	}
	have, readErr := os.ReadFile(path) // #nosec G304 -- fixed name in the config dir
	managed := readErr == nil && proxyUsersManaged(have)

	if on && user != "" && password != "" {
		if managed && proxyUsersMatch(have, user, password) {
			return false, nil
		}
		data, err := proxyUsersContent(user, password)
		if err != nil {
			return false, fmt.Errorf("hash the proxy password: %w", err)
		}
		if err := writeProxyUsersFile(path, data); err != nil {
			return false, err
		}
		return true, nil
	}
	if managed {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// requestProxyReload touches the trigger the proxy's watchdog polls every 2
// seconds; it regenerates squid.conf and reconfigures Squid.
func requestProxyReload(configDir string) error {
	// #nosec G306 -- reload trigger, must be readable by the proxy container
	return os.WriteFile(filepath.Join(configDir, ".reload-squid"), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644)
}

// syncProxyUsersAndReload runs SyncProxyUsers and, when the file changed,
// asks the proxy to reload at once rather than waiting for the caller to:
// until the proxy has read the new file, a credential it has not cached is
// refused. It returns the file name when the file could not be written, for
// the save's list of failed artefacts.
func (h *SettingsHandlers) syncProxyUsersAndReload() (failed string) {
	changed, err := h.SyncProxyUsers()
	if err != nil {
		log.Warn().Err(err).Msg("the proxy password file could not be written")
		return proxyUsersFileName
	}
	if changed {
		if err := requestProxyReload(h.cfg.ConfigDir); err != nil {
			log.Warn().Err(err).Msg("proxy reload trigger not written after the proxy password file changed")
		}
		log.Info().Msg("proxy password file brought in line with the stored proxy login settings")
	}
	return ""
}

// SyncProxyUsersAtStartup is syncProxyUsersAndReload for the server's start.
func (h *SettingsHandlers) SyncProxyUsersAtStartup() {
	if failed := h.syncProxyUsersAndReload(); failed != "" {
		log.Error().Str("file", failed).Msg("startup: the proxy password file could not be brought in line with the stored proxy login settings")
	}
}

// ProxyAuthStatus is what the proxy's generator last did about proxy login:
// State is off, enforced (Users accounts in the password file) or
// no_credentials (login is on and the file has no user, so the proxy
// refuses every client).
type ProxyAuthStatus struct {
	State     string `json:"state"`
	Users     int    `json:"users"`
	WrittenAt int64  `json:"written_at"`
}

// readProxyAuthStatus returns the proxy's record, or nil when there is none
// (a proxy older than this file, or one that has not generated a config yet)
// or it cannot be read.
func readProxyAuthStatus(configDir string) *ProxyAuthStatus {
	raw, err := os.ReadFile(filepath.Join(configDir, proxyAuthStatusFileName)) // #nosec G304 -- fixed name in the config dir
	if err != nil {
		return nil
	}
	var s struct {
		Version   int    `json:"version"`
		State     string `json:"state"`
		Users     *int   `json:"users"`
		WrittenAt int64  `json:"written_at"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Version != 1 || s.Users == nil {
		return nil
	}
	switch s.State {
	case "off", "enforced", "no_credentials":
		return &ProxyAuthStatus{State: s.State, Users: *s.Users, WrittenAt: s.WrittenAt}
	}
	return nil
}
