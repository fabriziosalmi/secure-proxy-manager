package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withOwnProxyGroup(t *testing.T) {
	t.Helper()
	old := proxyGroupID
	proxyGroupID = os.Getegid()
	t.Cleanup(func() { proxyGroupID = old })
}

var ldapComplete = map[string]string{
	settingProxyAuth: "true", settingProxyAuthSource: "ldap",
	settingLDAPURL: "ldaps://dc1.corp.example:636", settingLDAPBindDN: "cn=Proxy Bind,ou=Service Accounts,dc=corp,dc=example",
	settingLDAPBindPass: "bind pass with spaces!", settingLDAPUserBase: "ou=people,dc=corp,dc=example",
	settingLDAPUserFilter: "(sAMAccountName=%s)",
}

// The proxy's LDAP files follow the stored settings: the marker while login
// is on from LDAP, the conf and the bind password while they are complete
// (the password alone in its own file, group-readable for the helper), and
// nothing once the source is local again.
func TestTheProxyLDAPFilesFollowTheSettings(t *testing.T) {
	withOwnProxyGroup(t)
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	sh := NewSettingsHandlers(db, cfg)
	marker := filepath.Join(cfg.ConfigDir, ldapMarkerName)
	conf := filepath.Join(cfg.SecretsDir, ldapConfName)
	pass := filepath.Join(cfg.SecretsDir, ldapPasswordName)

	setSetting(t, sh, ldapComplete)
	if _, ok := readFile(t, marker); !ok {
		t.Error("no marker with login on from LDAP")
	}
	got, _ := readFile(t, conf)
	want := "LDAP_URL=ldaps://dc1.corp.example:636\nLDAP_BIND_DN=cn=Proxy Bind,ou=Service Accounts,dc=corp,dc=example\n" +
		"LDAP_USER_BASE=ou=people,dc=corp,dc=example\nLDAP_USER_FILTER=(sAMAccountName=%s)\n"
	if got != want {
		t.Errorf("conf = %q\nwant %q", got, want)
	}
	if p, _ := readFile(t, pass); p != "bind pass with spaces!" {
		t.Errorf("password file = %q", p)
	}
	if st, err := os.Stat(pass); err != nil || st.Mode().Perm() != 0o640 {
		t.Errorf("password file mode %v (%v), want 0640", st.Mode().Perm(), err)
	}
	if st, err := os.Stat(conf); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("conf mode %v (%v), want 0600", st.Mode().Perm(), err)
	}
	if strings.Contains(got, "bind pass") {
		t.Error("the password is in the conf too")
	}

	setSetting(t, sh, map[string]string{settingLDAPGroup: "proxy-users", settingLDAPGroupBase: "ou=groups,dc=corp,dc=example"})
	got, _ = readFile(t, conf)
	if !strings.HasSuffix(got, "LDAP_GROUP=proxy-users\nLDAP_GROUP_BASE=ou=groups,dc=corp,dc=example\nLDAP_GROUP_FILTER=(&(cn=%g)(member=%u))\n") {
		t.Errorf("conf with a group = %q", got)
	}

	setSetting(t, sh, map[string]string{settingProxyAuthSource: "local", settingProxyUsername: "office", settingProxyPassword: "correct-horse-battery"})
	for _, p := range []string{marker, conf, pass} {
		if _, ok := readFile(t, p); ok {
			t.Errorf("%s still there with the source local", filepath.Base(p))
		}
	}
}

// A stored value the directory settings would refuse (written past the API)
// leaves the marker without a conf: the proxy refuses every client rather
// than fall back to the local password file.
func TestAnIncompleteLDAPLoginKeepsTheMarkerAndNoConf(t *testing.T) {
	withOwnProxyGroup(t)
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	sh := NewSettingsHandlers(db, cfg)
	setSetting(t, sh, ldapComplete)
	if _, err := db.Exec(`UPDATE settings SET setting_value = 'http://dc1' WHERE setting_name = ?`, settingLDAPURL); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.SyncProxyLDAP(); err != nil {
		t.Fatal(err)
	}
	if _, ok := readFile(t, filepath.Join(cfg.ConfigDir, ldapMarkerName)); !ok {
		t.Error("marker removed")
	}
	for _, n := range []string{ldapConfName, ldapPasswordName} {
		if _, ok := readFile(t, filepath.Join(cfg.SecretsDir, n)); ok {
			t.Errorf("%s written from an invalid URL", n)
		}
	}
}

// Login on from LDAP needs the directory's URL, the search account and its
// password, and where users are: without them the save is refused, as a
// local login without its username and password is. The local credentials
// are not asked for.
func TestASaveOfLDAPLoginNeedsTheDirectory(t *testing.T) {
	withOwnProxyGroup(t)
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	sh := NewSettingsHandlers(db, cfg)
	w, resp := bulkUpdate(t, sh, "", map[string]string{settingProxyAuth: "true", settingProxyAuthSource: "ldap"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
	errs, _ := resp["errors"].(map[string]any)
	for _, k := range []string{settingLDAPURL, settingLDAPBindDN, settingLDAPBindPass, settingLDAPUserBase} {
		if errs[k] == nil {
			t.Errorf("no error for %s: %v", k, errs)
		}
	}
	for _, k := range []string{settingProxyUsername, settingProxyPassword} {
		if errs[k] != nil {
			t.Errorf("the local %s is asked for with the source LDAP", k)
		}
	}
	if w, resp := bulkUpdate(t, sh, "", ldapComplete); w.Code != http.StatusOK {
		t.Errorf("complete: %d %v", w.Code, resp)
	}
	if w, resp := bulkUpdate(t, sh, "", map[string]string{settingLDAPGroup: "proxy-users"}); w.Code != http.StatusBadRequest {
		t.Errorf("a group without its base: %d %v", w.Code, resp)
	}
}

func TestLDAPSettingsAreValidated(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	sh := NewSettingsHandlers(db, cfg)
	for k, v := range map[string]string{
		settingProxyAuthSource: "kerberos",
		settingLDAPURL:         "ldaps://dc1/ou=x",
		settingLDAPBindDN:      `cn=x" -H ldap://evil`,
		settingLDAPUserBase:    "ou=people#comment",
		settingLDAPUserFilter:  "(uid=alice)",
		settingLDAPGroupFilter: "(cn=%g)",
		settingLDAPGroup:       "proxy users",
	} {
		if w, _ := bulkUpdate(t, sh, "", map[string]string{k: v}); w.Code == http.StatusOK {
			t.Errorf("%s=%q was accepted", k, v)
		}
	}
	for k, v := range map[string]string{
		settingLDAPURL: "ldap://10.0.0.5:389", settingLDAPBindDN: "proxy@corp.example",
		settingLDAPUserFilter: "(&(objectClass=user)(sAMAccountName=%s))", settingLDAPGroupFilter: "(&(cn=%g)(member=%u))",
	} {
		if w, resp := bulkUpdate(t, sh, "", map[string]string{k: v}); w.Code != http.StatusOK {
			t.Errorf("%s=%q refused: %v", k, v, resp)
		}
	}
}

func TestTheProxyReportsLDAPLogin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, proxyAuthStatusFileName), []byte(`{"version":1,"state":"ldap","users":0,"written_at":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s := readProxyAuthStatus(dir); s == nil || s.State != "ldap" {
		t.Errorf("status = %+v", s)
	}
}
