package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func known(id string) bool { return id == "SQLi-015" || id == "XSS-003" || id == "H2-BEACON" }

func mustParse(t *testing.T, doc string) *Policy {
	t.Helper()
	p, err := Parse([]byte(doc), known)
	if err != nil {
		t.Fatalf("%s: %v", doc, err)
	}
	return p
}

// Each mistake in a file is refused with the entry it is about, so a policy
// the operator wrote is never one that silently does nothing.
func TestParseRefuses(t *testing.T) {
	for _, c := range []struct{ doc, want string }{
		{`{"version":2}`, "version 2"},
		{`{"version":1,"mode":"learn"}`, `mode "learn"`},
		{`{"version":1,"exeptions":[]}`, `unknown field "exeptions"`},
		{`{"version":1}{"version":1}`, "more than one"},
		{`{"version":1,"observe_rules":["SQLi-999"]}`, `"SQLi-999": no such rule`},
		{`{"version":1,"observe_rules":["CRS-94229"]}`, "six digits"},
		{`{"version":1,"observe_categories":[" "]}`, "empty name"},
		{`{"version":1,"exceptions":[{"rule":"SQLi-015"}]}`, "exceptions[0] (SQLi-015): no host, path or target"},
		{`{"version":1,"exceptions":[{"host":"a.example"}]}`, "a rule ID is required"},
		{`{"version":1,"exceptions":[{"rule":"SQLi-015","target":"ARGS:q"}]}`, "target is for CRS rules"},
		{`{"version":1,"exceptions":[{"rule":"CRS-942290","target":"NOPE:q"}]}`, `target "NOPE:q"`},
		{`{"version":1,"exceptions":[{"rule":"CRS-942290","target":"ARGS:"}]}`, "an empty key"},
		{`{"version":1,"exceptions":[{"rule":"CRS-942290","target":"ARGS:/(/"}]}`, `target "ARGS:/(/"`},
		{`{"version":1,"exceptions":[{"rule":"CRS-942290","host":"*.example.com"}]}`, `host "*.example.com"`},
		{`{"version":1,"exceptions":[{"rule":"CRS-942290","host":"example.com:443"}]}`, `host "example.com:443"`},
		{`{"version":1,"exceptions":[{"rule":"CRS-942290","path":"login"}]}`, `path "login"`},
	} {
		_, err := Parse([]byte(c.doc), known)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want it to say %q", c.doc, err, c.want)
		}
	}
	big := `{"version":1,"exceptions":[` + strings.Repeat(`{"rule":"SQLi-015","host":"a.example"},`, MaxExceptions) + `{"rule":"SQLi-015","host":"a.example"}]}`
	if _, err := Parse([]byte(big), known); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("%d exceptions accepted: %v", MaxExceptions+1, err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p, err := Load(filepath.Join(dir, "missing.json"), known)
	if err != nil || p.Exceptions() != 0 || p.Observe() || p.Digest() != "empty" || !p.Inert() {
		t.Errorf("a missing file is the empty policy: %+v %v", p, err)
	}
	path := filepath.Join(dir, "p.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"exceptions":[{"rule":"SQLi-015","host":"a.example"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err = Load(path, known)
	if err != nil || p.Exceptions() != 1 || len(p.Digest()) != 64 || p.Inert() {
		t.Errorf("a one-exception file: %+v %v", p, err)
	}
	if err := os.WriteFile(path, make([]byte, MaxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, known); err == nil || !strings.Contains(err.Error(), "over") {
		t.Errorf("an oversize file: %v", err)
	}
}

// A policy with only the whole-WAF mode changes no single rule.
func TestInert(t *testing.T) {
	if !mustParse(t, `{"version":1,"mode":"observe"}`).Inert() {
		t.Error("observe mode alone is not inert")
	}
	for _, doc := range []string{
		`{"version":1,"observe_rules":["XSS-003"]}`,
		`{"version":1,"observe_categories":["SSRF"]}`,
		`{"version":1,"exceptions":[{"rule":"XSS-003","path":"/a"}]}`,
	} {
		if mustParse(t, doc).Inert() {
			t.Errorf("%s is inert", doc)
		}
	}
}

func TestForMatchesHostAndPath(t *testing.T) {
	p := mustParse(t, `{"version":1,"exceptions":[
		{"rule":"SQLi-015","host":"shop.example"},
		{"rule":"XSS-003","host":".cdn.example","path":"/img/"},
		{"rule":"H2-BEACON","path":"/collect"},
		{"rule":"CRS-942290","host":"Login.Example.","target":"ARGS:Password"},
		{"rule":"CRS-930120","host":"ads.example","target":"ARGS_NAMES:/^ep\\./"},
		{"rule":"CRS-941120","host":"news.example","target":"REQUEST_FILENAME"},
		{"rule":"CRS-932235","host":"t.example"}
	]}`)
	for _, c := range []struct {
		host, path, rule string
		want             bool
	}{
		{"shop.example", "/", "SQLi-015", true},
		{"SHOP.example:443", "/x", "SQLi-015", true},
		{"shop.example.", "/x", "SQLi-015", true},
		{"www.shop.example", "/", "SQLi-015", false},
		{"cdn.example", "/img/a.png", "XSS-003", true},
		{"eu.cdn.example", "/img/a.png", "XSS-003", true},
		{"evilcdn.example", "/img/a.png", "XSS-003", false},
		{"cdn.example", "/js/a.js", "XSS-003", false},
		{"any.example", "/collect?x", "H2-BEACON", true},
		{"any.example", "/other", "H2-BEACON", false},
	} {
		if got := p.For(c.host, c.path).Skip(c.rule); got != c.want {
			t.Errorf("%s%s %s: skip %v, want %v", c.host, c.path, c.rule, got, c.want)
		}
	}
	x := p.For("login.example", "/").CRS().Exclusions
	if len(x) != 1 || x[0].Rule != 942290 || !x[0].Target || x[0].Variable != variables.Args || x[0].Key != "password" {
		t.Errorf("CRS target exclusion: %+v", x)
	}
	if x := p.For("ads.example", "/").CRS().Exclusions; len(x) != 1 || x[0].KeyRx == nil || !x[0].KeyRx.MatchString("ep.profile_hash") || x[0].Variable != variables.ArgsNames {
		t.Errorf("CRS regex key exclusion: %+v", x)
	}
	if x := p.For("news.example", "/").CRS().Exclusions; len(x) != 1 || x[0].Variable != variables.RequestFilename || x[0].Key != "" || x[0].KeyRx != nil {
		t.Errorf("CRS whole-variable exclusion: %+v", x)
	}
	if x := p.For("t.example", "/").CRS().Exclusions; len(x) != 1 || x[0].Target || x[0].Rule != 932235 {
		t.Errorf("CRS whole-rule exclusion: %+v", x)
	}
	if x := p.For("other.example", "/").CRS().Exclusions; len(x) != 0 {
		t.Errorf("exclusions for a host with none: %+v", x)
	}
}

func TestObserve(t *testing.T) {
	p := mustParse(t, `{"version":1,"observe_rules":["XSS-003","CRS-942290"],"observe_categories":["SSRF","CRS_RCE"]}`)
	a := p.For("x.example", "/")
	if !a.ObserveMatch("XSS-003", "XSS_ATTACKS") || !a.ObserveMatch("SSRF-006", "SSRF") || a.ObserveMatch("SQLi-015", "SQL_INJECTION") {
		t.Error("spm observe by rule and category")
	}
	obs := a.CRS().Observe
	if obs == nil || !obs(942290) || !obs(932235) || obs(941120) {
		t.Error("CRS observe by rule and family")
	}
	if p.For("x.example", "/").CRS().Observe == nil || Empty().For("x", "/").CRS().Observe != nil {
		t.Error("CRS observe is nil only without log-only rules")
	}
}

func TestRequestHost(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM": "example.com", "example.com:8443": "example.com", "example.com.": "example.com",
		"[2001:db8::1]:443": "2001:db8::1", "[2001:db8::1]": "2001:db8::1", "192.0.2.1:80": "192.0.2.1",
	} {
		if got := RequestHost(in); got != want {
			t.Errorf("RequestHost(%q) = %q, want %q", in, got, want)
		}
	}
}
