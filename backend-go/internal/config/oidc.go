package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// OIDC is sign-in to the dashboard with an OpenID Connect provider
// (authorization code with PKCE). It is off unless OIDC_ISSUER is set; set,
// the rest must be right or the backend refuses to start, so a half-written
// configuration never runs as something other than what was meant.
type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string // empty for a public client (PKCE alone)
	RedirectURL  string // https://<host>/api/auth/oidc/callback, as registered at the provider
	Scopes       []string
	// Who may sign in: an email in AllowedEmails, or a member of a group in
	// AllowedGroups (read from GroupsClaim). At least one list is required:
	// nobody is let in by default.
	AllowedEmails []string
	AllowedGroups []string
	GroupsClaim   string
	// Session is how long a sign-in lasts; it is renewed only by signing in
	// again, so access removed at the provider ends within it.
	Session time.Duration
	// Label names the provider on the sign-in button.
	Label string
}

// Enabled reports whether OIDC sign-in is configured.
func (o OIDC) Enabled() bool { return o.Issuer != "" }

// Fingerprint changes when the provider, the client or who may sign in
// changes. Sessions carry it (claim "ob"), so changing the configuration ends
// the sessions it no longer allows, as a password change does for the admin.
func (o OIDC) Fingerprint() string {
	emails := append([]string(nil), o.AllowedEmails...)
	groups := append([]string(nil), o.AllowedGroups...)
	sort.Strings(emails)
	sort.Strings(groups)
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"spm-ob", o.Issuer, o.ClientID, o.GroupsClaim,
		strings.Join(emails, ","), strings.Join(groups, ","),
	}, "\x00")))
	return hex.EncodeToString(sum[:12])
}

func splitList(v string, lower bool) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if lower {
			s = strings.ToLower(s)
		}
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// LoadOIDC reads the OIDC_* variables through get (os.Getenv in Load).
func LoadOIDC(get func(string) string) (OIDC, error) {
	o := OIDC{Issuer: strings.TrimRight(strings.TrimSpace(get("OIDC_ISSUER")), "/")}
	if o.Issuer == "" {
		for _, k := range []string{"OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URL", "OIDC_ALLOWED_EMAILS", "OIDC_ALLOWED_GROUPS"} {
			if strings.TrimSpace(get(k)) != "" {
				return OIDC{}, errors.New(k + " is set but OIDC_ISSUER is not: set the issuer, or remove the OIDC_* variables")
			}
		}
		return OIDC{}, nil
	}
	o.ClientID = strings.TrimSpace(get("OIDC_CLIENT_ID"))
	o.ClientSecret = strings.TrimSpace(get("OIDC_CLIENT_SECRET"))
	o.RedirectURL = strings.TrimSpace(get("OIDC_REDIRECT_URL"))
	o.AllowedEmails = splitList(get("OIDC_ALLOWED_EMAILS"), true)
	o.AllowedGroups = splitList(get("OIDC_ALLOWED_GROUPS"), false)
	o.GroupsClaim = strings.TrimSpace(get("OIDC_GROUPS_CLAIM"))
	if o.GroupsClaim == "" {
		o.GroupsClaim = "groups"
	}
	// Scopes are written space-separated in OAuth; commas are accepted too.
	o.Scopes = strings.FieldsFunc(get("OIDC_SCOPES"), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	if len(o.Scopes) == 0 {
		o.Scopes = []string{"openid", "email", "profile"}
	}
	o.Label = strings.TrimSpace(get("OIDC_LABEL"))
	if o.Label == "" {
		o.Label = "single sign-on"
	}
	o.Session = time.Hour
	if v := strings.TrimSpace(get("OIDC_SESSION_DURATION")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 5*time.Minute || d > 24*time.Hour {
			return OIDC{}, errors.New("OIDC_SESSION_DURATION: a duration from 5m to 24h, such as 1h")
		}
		o.Session = d
	}

	iss, err := url.Parse(o.Issuer)
	if err != nil || iss.Scheme != "https" || iss.Host == "" {
		return OIDC{}, errors.New("OIDC_ISSUER: the provider's https URL, as its discovery document gives it")
	}
	if o.ClientID == "" {
		return OIDC{}, errors.New("OIDC_CLIENT_ID is required with OIDC_ISSUER")
	}
	red, err := url.Parse(o.RedirectURL)
	// https, or http on a loopback host (a local test setup).
	schemeOK := err == nil && (red.Scheme == "https" || red.Scheme == "http" && isLoopbackHost(red.Hostname()))
	if !schemeOK || red.Host == "" || red.Path != "/api/auth/oidc/callback" {
		return OIDC{}, errors.New("OIDC_REDIRECT_URL: https://<dashboard host>/api/auth/oidc/callback, as registered at the provider")
	}
	if len(o.AllowedEmails) == 0 && len(o.AllowedGroups) == 0 {
		return OIDC{}, errors.New("OIDC_ALLOWED_EMAILS or OIDC_ALLOWED_GROUPS is required: nobody is let in by default")
	}
	return o, nil
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// loadOIDCOrExit is LoadOIDC on the environment, fatal on an error.
func loadOIDCOrExit() OIDC {
	o, err := LoadOIDC(os.Getenv)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid OIDC configuration")
	}
	return o
}
