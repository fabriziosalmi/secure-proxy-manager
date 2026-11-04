package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func valid() map[string]string {
	return map[string]string{
		"OIDC_ISSUER":         "https://id.example.com/realms/spm/",
		"OIDC_CLIENT_ID":      "spm",
		"OIDC_REDIRECT_URL":   "https://spm.example.com:8443/api/auth/oidc/callback",
		"OIDC_ALLOWED_EMAILS": " Admin@Example.com , ops@example.com",
	}
}

func TestOIDCIsOffWithoutAnIssuer(t *testing.T) {
	o, err := LoadOIDC(env(nil))
	if err != nil || o.Enabled() {
		t.Fatalf("no variables: %+v %v", o, err)
	}
}

func TestOIDCReadsAValidConfiguration(t *testing.T) {
	o, err := LoadOIDC(env(valid()))
	if err != nil {
		t.Fatal(err)
	}
	if !o.Enabled() || o.Issuer != "https://id.example.com/realms/spm" || o.ClientID != "spm" {
		t.Errorf("%+v", o)
	}
	if strings.Join(o.AllowedEmails, ",") != "admin@example.com,ops@example.com" {
		t.Errorf("emails %v: trimmed and lowercased", o.AllowedEmails)
	}
	if o.Session != time.Hour || o.GroupsClaim != "groups" || strings.Join(o.Scopes, " ") != "openid email profile" || o.Label == "" {
		t.Errorf("defaults %+v", o)
	}
}

func TestOIDCScopesAreReadSpaceOrCommaSeparated(t *testing.T) {
	for _, v := range []string{"openid email groups", "openid,email,groups", " openid, email  groups "} {
		m := valid()
		m["OIDC_SCOPES"] = v
		o, err := LoadOIDC(env(m))
		if err != nil || strings.Join(o.Scopes, "|") != "openid|email|groups" {
			t.Errorf("OIDC_SCOPES=%q: %q %v", v, o.Scopes, err)
		}
	}
}

func TestOIDCRefusesAHalfWrittenConfiguration(t *testing.T) {
	for name, change := range map[string]map[string]string{
		"client id without issuer": {"OIDC_ISSUER": ""},
		"issuer over http":         {"OIDC_ISSUER": "http://id.example.com"},
		"no client id":             {"OIDC_CLIENT_ID": ""},
		"no redirect":              {"OIDC_REDIRECT_URL": ""},
		"redirect elsewhere":       {"OIDC_REDIRECT_URL": "https://spm.example.com/login"},
		"redirect over http":       {"OIDC_REDIRECT_URL": "http://spm.example.com/api/auth/oidc/callback"},
		"nobody allowed":           {"OIDC_ALLOWED_EMAILS": ""},
		"session too long":         {"OIDC_SESSION_DURATION": "48h"},
		"session not a duration":   {"OIDC_SESSION_DURATION": "1 hour"},
		"password login not bool":  {"OIDC_PASSWORD_LOGIN": "only from here"},
		"password off, no issuer": {
			"OIDC_ISSUER": "", "OIDC_CLIENT_ID": "", "OIDC_REDIRECT_URL": "",
			"OIDC_ALLOWED_EMAILS": "", "OIDC_PASSWORD_LOGIN": "false",
		},
	} {
		m := valid()
		for k, v := range change {
			m[k] = v
		}
		if _, err := LoadOIDC(env(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A group alone is enough; http is fine for a loopback redirect (testing).
	m := valid()
	m["OIDC_ALLOWED_EMAILS"], m["OIDC_ALLOWED_GROUPS"] = "", "spm-admins"
	m["OIDC_REDIRECT_URL"] = "http://localhost:8443/api/auth/oidc/callback"
	if _, err := LoadOIDC(env(m)); err != nil {
		t.Errorf("groups only, loopback redirect: %v", err)
	}
}

func TestOIDCPasswordLoginStaysOnUnlessTurnedOff(t *testing.T) {
	m := valid()
	if o, err := LoadOIDC(env(m)); err != nil || o.PasswordOff {
		t.Fatalf("default: %+v %v", o, err)
	}
	m["OIDC_PASSWORD_LOGIN"] = "false"
	if o, err := LoadOIDC(env(m)); err != nil || !o.PasswordOff {
		t.Fatalf("false: %+v %v", o, err)
	}
	// Left at true without a provider, as a copied .env may have it.
	if o, err := LoadOIDC(env(map[string]string{"OIDC_PASSWORD_LOGIN": "true"})); err != nil || o.Enabled() || o.PasswordOff {
		t.Fatalf("true without issuer: %+v %v", o, err)
	}
}

func TestTheOIDCFingerprintFollowsWhoMaySignIn(t *testing.T) {
	a, _ := LoadOIDC(env(valid()))
	m := valid()
	m["OIDC_ALLOWED_EMAILS"] = "ops@example.com,admin@example.com"
	b, _ := LoadOIDC(env(m))
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("the order of the list changed the fingerprint")
	}
	m["OIDC_ALLOWED_EMAILS"] = "ops@example.com"
	c, _ := LoadOIDC(env(m))
	if a.Fingerprint() == c.Fingerprint() {
		t.Error("removing a user did not change the fingerprint")
	}
}
