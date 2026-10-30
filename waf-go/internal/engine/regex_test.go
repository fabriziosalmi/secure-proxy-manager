package engine

import (
	"math/rand"
	"regexp/syntax"
	"secure-proxy-waf/internal/regexsample"
	"strings"
	"testing"

	re2 "github.com/wasilibs/go-re2"
)

// Every built-in rule compiles in RE2, so none silently stays on Go's regexp.
func TestEveryRuleCompilesInRE2(t *testing.T) {
	for _, cr := range blockRules {
		for _, rule := range cr.Rules {
			if _, err := re2.Compile(rule.Pattern.String()); err != nil {
				t.Errorf("%s: %v", rule.ID, err)
			}
		}
	}
}

// RE2 and Go's regexp agree on every rule: the same verdict on strings drawn
// from each pattern's syntax tree (matching ones, near misses, case folds),
// alone and inside other text.
func TestRE2AgreesWithGoRegexp(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	for _, cr := range blockRules {
		for _, rule := range cr.Rules {
			c, err := re2.Compile(rule.Pattern.String())
			if err != nil {
				continue // TestEveryRuleCompilesInRE2 reports it
			}
			parsed, err := syntax.Parse(rule.Pattern.String(), syntax.Perl)
			if err != nil {
				t.Fatalf("%s: %v", rule.ID, err)
			}
			parsed = parsed.Simplify()
			for i := 0; i < 1500; i++ {
				var b strings.Builder
				regexsample.Draw(parsed, r, &b)
				s := contextWords[r.Intn(len(contextWords))] + b.String() + contextWords[r.Intn(len(contextWords))]
				if i%4 == 3 && len(s) > 2 {
					k := r.Intn(len(s))
					s = s[:k] + s[k+1:] // a near miss
				}
				if g, e := rule.Pattern.MatchString(s), c.MatchString(AsRE2Input(s)); g != e {
					t.Errorf("%s on %q: Go %v, RE2 %v", rule.ID, s, g, e)
					break
				}
			}
		}
	}
}

// With WAF_REGEX_ENGINE=re2 the matcher runs the RE2 form of every rule.
func TestMatcherUsesRE2(t *testing.T) {
	if RegexEngine() != "re2" {
		t.Skip("WAF_REGEX_ENGINE is not re2")
	}
	m := compiledRE2.Load()
	if m == nil {
		t.Fatal("no RE2 forms built")
	}
	n := 0
	for _, cr := range blockRules {
		n += len(cr.Rules)
	}
	if len(*m) != n {
		t.Errorf("%d RE2 forms for %d rules", len(*m), n)
	}
}
