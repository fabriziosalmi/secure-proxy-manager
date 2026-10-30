package engine

import (
	"math/rand"
	"regexp/syntax"
	"secure-proxy-waf/internal/regexsample"
	"strings"
	"testing"
)

var contextWords = []string{"order", "the", "invoice", "x", "", " ", "\n", "a=b", "&", "{\"k\":", "1", "\t"}

// The gates are sound: a string a gated rule matches, in the input or in its
// compacted form, alone or inside other text, passes the rule's gate. Each
// rule gets thousands of draws from its own pattern, case folds included,
// and draws with whitespace inserted, which only the compacted form matches.
func TestGatesAreImpliedByTheirRules(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for _, cr := range blockRules {
		for _, rule := range cr.Rules {
			gate, ok := ruleGates[rule.ID]
			if !ok {
				continue
			}
			parsed, err := syntax.Parse(rule.Pattern.String(), syntax.Perl)
			if err != nil {
				t.Fatalf("%s: %v", rule.ID, err)
			}
			parsed = parsed.Simplify()
			matched, compactOnly := 0, 0
			for i := 0; i < 6000; i++ {
				var b strings.Builder
				regexsample.Draw(parsed, r, &b)
				s := b.String()
				if i%3 == 1 && len(s) > 1 {
					// Whitespace inside: only the compacted form may match.
					k := 1 + r.Intn(len(s)-1)
					s = s[:k] + []string{" ", "\t", "\n "}[r.Intn(3)] + s[k:]
				}
				input := contextWords[r.Intn(len(contextWords))] + s + contextWords[r.Intn(len(contextWords))]
				compact := compactInput(input)
				hitRaw := rule.Pattern.MatchString(input)
				hitCompact := rule.Pattern.MatchString(compact)
				if !hitRaw && !hitCompact {
					continue
				}
				matched++
				if !hitRaw {
					compactOnly++
				}
				f := gatherFacts(input, prefilterScreen(input))
				if !gate(&f) {
					t.Errorf("%s: the gate is false on %q, which the rule matches (raw %v, compacted %v)", rule.ID, input, hitRaw, hitCompact)
					break
				}
			}
			if matched < 100 {
				t.Errorf("%s: only %d of 6000 draws matched; the sampler does not cover this pattern", rule.ID, matched)
			}
		}
	}
}

// A gate is for a rule the literal screen does not gate, and names a rule
// that exists.
func TestEveryGateIsForAnUngatedRule(t *testing.T) {
	ids := map[string]bool{}
	for _, cr := range blockRules {
		for _, rule := range cr.Rules {
			ids[rule.ID] = true
		}
	}
	for id := range ruleGates {
		if !ids[id] {
			t.Errorf("gate for %s, which is not a rule", id)
		}
		if _, ungated := activePrefilter.ungated[id]; !ungated {
			t.Errorf("gate for %s, which the literal screen already gates", id)
		}
	}
}

// On benign text the gates leave few rules to scan, and an attack in the
// same text still matches.
func TestGatesSkipRulesOnBenignText(t *testing.T) {
	benign := NormalizeInput(strings.Repeat("the order was shipped on monday and the invoice is attached. ", 200))
	active, ok := prefilterActive(benign)
	if !ok {
		t.Fatal("no pre-filter")
	}
	scanned := 0
	for id := range activePrefilter.ungated {
		if _, on := active[id]; on {
			scanned++
		}
	}
	if scanned > 3 {
		t.Errorf("%d rules with no literal still scanned on benign text", scanned)
	}
	e := New(Config{BlockThreshold: 10})
	for _, attack := range []string{
		"note: 4111111111111111 exp 12/29",
		"x' or 1=1 -- ",
		"user=admin&password=hunter22",
		"pay to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT now",
		"<img src=x onerror=alert(1)>",
	} {
		_, score := e.MatchRulesScored(NormalizeInput(benign[:200] + attack + benign[:200]))
		if score == 0 {
			t.Errorf("%q in benign text scores 0", attack)
		}
	}
}

// compactBytes removes what compactInput's \s+ removes, and nothing else.
func TestCompactBytesIsCompactInput(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	const pool = " \t\n\v\f\rab\xe2\x84\xaa  x="
	for i := 0; i < 5000; i++ {
		var b strings.Builder
		for n := r.Intn(30); n > 0; n-- {
			b.WriteByte(pool[r.Intn(len(pool))])
		}
		s := b.String()
		if got, want := compactBytes(s), compactInput(s); got != want {
			t.Fatalf("%q: compactBytes %q, compactInput %q", s, got, want)
		}
	}
}
