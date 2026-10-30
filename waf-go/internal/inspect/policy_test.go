package inspect

import (
	"strings"
	"testing"

	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/policy"
)

func pol(t *testing.T, doc string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(doc), engine.KnownRuleID)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// XSS-001 is a tier-1 rule that reaches the threshold alone, and the scan
// stops there. An exception for it must not stop the scan: the SQL
// injection beside it, found by a later tier, still blocks. Applied to the
// result instead of while scanning, the exception let this request through.
func TestExceptionDoesNotHideLaterTiers(t *testing.T) {
	const u = "GET http://a.example/x?u='%20or%201=1--%20<script>alert(1)</script> HTTP/1.1\r\nHost: a.example\r\n\r\n"
	in, _ := Evaluate(newEngine(), nil, nil, req(t, u), "192.0.2.20")
	if !in.Blocked() || ids(in) != "XSS-001" {
		t.Fatalf("without a policy: blocked %v by %s, want XSS-001 alone", in.Blocked(), ids(in))
	}
	p := pol(t, `{"version":1,"exceptions":[{"rule":"XSS-001","host":"a.example"}]}`)
	in, _ = Evaluate(newEngine(), nil, p, req(t, u), "192.0.2.21")
	if !in.Blocked() || strings.Contains(ids(in), "XSS-001") || !strings.Contains(ids(in), "SQLi") {
		t.Errorf("XSS-001 excepted: blocked %v by %s, want a SQLi block", in.Blocked(), ids(in))
	}
	if strings.Join(in.Excepted, ",") != "XSS-001" {
		t.Errorf("excepted %v, want XSS-001", in.Excepted)
	}
	// The exception is for a.example only.
	other := strings.ReplaceAll(u, "a.example", "b.example")
	in, _ = Evaluate(newEngine(), nil, p, req(t, other), "192.0.2.22")
	if !strings.Contains(ids(in), "XSS-001") || len(in.Excepted) != 0 {
		t.Errorf("another host: %s, excepted %v", ids(in), in.Excepted)
	}
}

// A rule or category the policy observes is reported with no score.
func TestObservedSPMRuleScoresNothing(t *testing.T) {
	const u = "GET http://a.example/x?x=<img%20src=x%20onerror=alert(1)> HTTP/1.1\r\nHost: a.example\r\n\r\n"
	for _, doc := range []string{
		`{"version":1,"observe_rules":["XSS-003"]}`,
		`{"version":1,"observe_categories":["XSS_ATTACKS"]}`,
	} {
		in, _ := Evaluate(newEngine(), nil, pol(t, doc), req(t, u), "192.0.2.23")
		if in.Blocked() || in.Score != 0 || !strings.Contains(ids(in), "XSS-003") {
			t.Errorf("%s: blocked %v, score %d, rules %s", doc, in.Blocked(), in.Score, ids(in))
		}
	}
}

// Heuristic results go through the policy too.
func TestExceptionReachesSignals(t *testing.T) {
	e := newEngine()
	p := pol(t, `{"version":1,"exceptions":[{"rule":"WAF-BODY-OVERSIZE","host":"up.example"}]}`)
	in := &Inspection{Eng: e, Policy: p, RawURL: "http://up.example/"}
	in.filter(req(t, "GET http://up.example/ HTTP/1.1\r\nHost: up.example\r\n\r\n"))
	in.Add(engine.MatchResult{RuleID: "WAF-BODY-OVERSIZE", Category: "BODY_OVERSIZE", Score: 4})
	in.Add(engine.MatchResult{RuleID: "ML-DGA-001", Category: "DGA_DOMAIN", Score: 6})
	if in.Score != 6 || ids(in) != "ML-DGA-001" || strings.Join(in.Excepted, ",") != "WAF-BODY-OVERSIZE" {
		t.Errorf("score %d, rules %s, excepted %v", in.Score, ids(in), in.Excepted)
	}
}

// In observe mode the WAF decides as in block mode and does not act on it.
func TestObserveModeDecidesAndDoesNotBlock(t *testing.T) {
	const u = "GET http://a.example/x?q='%20union%20select%20password%20from%20users-- HTTP/1.1\r\nHost: a.example\r\n\r\n"
	in, _ := Evaluate(newEngine(), nil, pol(t, `{"version":1,"mode":"observe"}`), req(t, u), "192.0.2.24")
	if in.Blocked() || !in.WouldBlock() || !strings.Contains(ids(in), "SQLi-001") {
		t.Errorf("observe mode: blocked %v, would block %v, rules %s", in.Blocked(), in.WouldBlock(), ids(in))
	}
}

// A policy that changes no rule gives the verdict no policy gives.
func TestInertPolicyIsNoPolicy(t *testing.T) {
	for _, u := range []string{
		"GET http://a.example/x?q='%20union%20select%20password%20from%20users-- HTTP/1.1\r\nHost: a.example\r\n\r\n",
		"GET http://a.example/ok?id=7 HTTP/1.1\r\nHost: a.example\r\n\r\n",
	} {
		a, _ := Evaluate(newEngine(), nil, nil, req(t, u), "192.0.2.25")
		b, _ := Evaluate(newEngine(), nil, policy.Empty(), req(t, u), "192.0.2.25")
		if a.Blocked() != b.Blocked() || a.Score != b.Score || ids(a) != ids(b) {
			t.Errorf("%s: no policy %v/%d/%s, empty policy %v/%d/%s", u, a.Blocked(), a.Score, ids(a), b.Blocked(), b.Score, ids(b))
		}
	}
}

func ids(in *Inspection) string {
	r, _ := in.Verdict()
	return strings.Join(r, ",")
}

// The CRS half under a policy, through Evaluate as the WAF runs it: an
// observed CRS rule is reported with its family and does not block; an
// exception on a host and an argument lets that host through and no other.
func TestCRSUnderAPolicy(t *testing.T) {
	const u = "GET http://tienda.example/tienda1/publico/autenticar.jsp?modo=entrar&login=caria&pwd=EnSaCad%24oRa&remember=on HTTP/1.1\r\nHost: tienda.example\r\n\r\n"
	in, _ := Evaluate(newEngine(), crsPL1, nil, req(t, u), "192.0.2.30")
	if !in.Blocked() || !strings.Contains(ids(in), "CRS-942290") {
		t.Fatalf("no policy: blocked %v by %s, want CRS-942290", in.Blocked(), ids(in))
	}

	in, _ = Evaluate(newEngine(), crsPL1, pol(t, `{"version":1,"observe_rules":["CRS-942290"]}`), req(t, u), "192.0.2.31")
	_, cats := in.Verdict()
	if in.Blocked() || !strings.Contains(ids(in), "CRS-942290") || !strings.Contains(strings.Join(cats, ","), "CRS_SQLI") {
		t.Errorf("CRS-942290 observed: blocked %v, rules %s, categories %v", in.Blocked(), ids(in), cats)
	}

	ex := pol(t, `{"version":1,"exceptions":[{"rule":"CRS-942290","host":"tienda.example","target":"ARGS:pwd"}]}`)
	if in, _ = Evaluate(newEngine(), crsPL1, ex, req(t, u), "192.0.2.32"); in.Blocked() {
		t.Errorf("CRS-942290 off ARGS:pwd on tienda.example: blocked by %s", ids(in))
	}
	other := strings.ReplaceAll(u, "tienda.example", "shop.example")
	if in, _ = Evaluate(newEngine(), crsPL1, ex, req(t, other), "192.0.2.33"); !in.Blocked() {
		t.Error("the exception for tienda.example let another host through")
	}
}
