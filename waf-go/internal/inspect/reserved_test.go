package inspect

import (
	"testing"
)

// A random name under a special-use top-level domain is a client's probe,
// not a generated domain: the same label under .com is still one, and a
// lookalike of a real name is still flagged.
func TestReputationSkipsReservedNames(t *testing.T) {
	has := func(host, rule string) bool {
		in, _ := Evaluate(newEngine(), nil, nil, req(t, "CONNECT "+host+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), "192.0.2.1")
		for _, m := range in.Matches {
			if m.RuleID == rule {
				return true
			}
		}
		return false
	}
	const label = "this-url-does-not-exist-7d1e5a90-3b2c-4f8e-9a61-c0d4e2b7f835"
	if !has(label+".com:443", "ML-DGA-001") {
		t.Fatalf("%s.com is not flagged as generated: the control does not hold", label)
	}
	for _, h := range []string{label + ".invalid:443", label + ".test:443", label + ".example:443", label + ".localhost:443"} {
		if has(h, "ML-DGA-001") {
			t.Errorf("%s flagged as a generated domain", h)
		}
	}
	if !has("paypa1.com:443", "ML-TYPO-001") {
		t.Error("paypa1.com is not flagged as a typosquat")
	}
	if has("paypa1.test:443", "ML-TYPO-001") {
		t.Error("paypa1.test flagged as a typosquat")
	}
}
