package crs

import (
	"regexp"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

// A CSIC false positive left at paranoia 1: a password with a $ in it reads
// as SQL to 942290.
const csicPassword = "GET http://localhost:8080/tienda1/publico/autenticar.jsp?modo=entrar&login=caria&pwd=EnSaCad%24oRa&remember=on HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"

// The anomaly score CRS computes is the sum of each scoring rule's severity
// weight, once per matched variable. Taking an observed rule's share off
// rests on it; wafeval checks it on every corpus.
func TestInboundIsTheSumOfContrib(t *testing.T) {
	e := newPL1(t)
	form := "user=admin&pass=1%27%20UNION%20SELECT%20password%20FROM%20users--&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	for name, raw := range map[string]string{
		"sqli and xss in a form": "POST http://shop.example/login HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + itoa(len(form)) + "\r\n\r\n" + form,
		"traversal in two args":  "GET http://shop.example/a?f=../../../../etc/passwd&g=../../../../etc/shadow HTTP/1.1\r\nHost: shop.example\r\n\r\n",
		"csic password":          csicPassword,
	} {
		r := req(t, raw)
		body := []byte(nil)
		if strings.HasPrefix(raw, "POST") {
			body = []byte(form)
		}
		res := e.Inspect(r, body, "192.0.2.1", false)
		sum := 0
		for _, w := range res.Contrib {
			sum += w
		}
		if !res.Blocked || res.Inbound == 0 || res.Inbound != sum {
			t.Errorf("%s: blocked %v, inbound %d, sum of contrib %d %v", name, res.Blocked, res.Inbound, sum, res.Contrib)
		}
	}
}

// An exception on one argument takes that argument out of the rule and
// nothing else: the same value in another argument still blocks.
func TestExclusionOfOneTarget(t *testing.T) {
	e := newPL1(t)
	if res := e.Inspect(req(t, csicPassword), nil, "192.0.2.1", false); !res.Blocked || !strings.Contains(strings.Join(res.Rules, ","), "942290") {
		t.Fatalf("the residual no longer reproduces: %+v", res)
	}
	pwd := Policy{Exclusions: []Exclusion{{Rule: 942290, Target: true, Variable: variables.Args, Key: "pwd"}}}
	if res := e.InspectWith(req(t, csicPassword), nil, "192.0.2.1", false, pwd); res.Blocked {
		t.Errorf("942290 off ARGS:pwd still blocks: %+v", res)
	}
	other := strings.Replace(csicPassword, "pwd=", "note=", 1)
	if res := e.InspectWith(req(t, other), nil, "192.0.2.1", false, pwd); !res.Blocked {
		t.Errorf("the same value in another argument passes: %+v", res)
	}
	rx := Policy{Exclusions: []Exclusion{{Rule: 942290, Target: true, Variable: variables.Args, KeyRx: regexp.MustCompile(`^(pwd|password)$`)}}}
	if res := e.InspectWith(req(t, csicPassword), nil, "192.0.2.1", false, rx); res.Blocked {
		t.Errorf("942290 off ARGS:/^(pwd|password)$/ still blocks: %+v", res)
	}
	whole := Policy{Exclusions: []Exclusion{{Rule: 942290}}}
	if res := e.InspectWith(req(t, other), nil, "192.0.2.1", false, whole); res.Blocked {
		t.Errorf("942290 removed still blocks: %+v", res)
	}
}

// An observed rule runs and is reported, and does not block on its own.
// Another rule that blocks still blocks.
func TestObservedRuleIsReportedAndDoesNotBlock(t *testing.T) {
	e := newPL1(t)
	obs := Policy{Observe: func(id int) bool { return id == 942290 }}
	res := e.InspectWith(req(t, csicPassword), nil, "192.0.2.1", false, obs)
	if res.Blocked || strings.Contains(strings.Join(res.Rules, ","), "942290") || strings.Join(res.Observed, ",") != "942290" {
		t.Errorf("942290 observed: %+v", res)
	}
	traversal := req(t, "GET http://localhost:8080/a?pwd=EnSaCad%24oRa&f=../../../../etc/passwd HTTP/1.1\r\nHost: localhost:8080\r\n\r\n")
	if res := e.InspectWith(traversal, nil, "192.0.2.1", false, obs); !res.Blocked || res.Score >= res.Inbound {
		t.Errorf("a traversal with an observed 942290 beside it: %+v", res)
	}
}

// 920440 is a chain: the first link matches the file name and sets
// tx.extension, the second scores. Counted once per matched variable of
// every link, its share was 10 for an inbound score of 5 (2,249 mismatches
// in wafeval's check).
func TestChainScoresOnceInItsLastLink(t *testing.T) {
	e := newPL1(t)
	res := e.Inspect(req(t, "GET http://shop.example/backup/site.bak HTTP/1.1\r\nHost: shop.example\r\n\r\n"), nil, "192.0.2.1", false)
	if !res.Blocked || res.Contrib["920440"] != 5 || res.Inbound != 5 {
		t.Errorf("920440: blocked %v, contrib %v, inbound %d", res.Blocked, res.Contrib, res.Inbound)
	}
}
