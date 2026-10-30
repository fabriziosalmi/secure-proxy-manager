package engine

import (
	"regexp"
	"testing"
	"time"

	re2 "github.com/wasilibs/go-re2"
)

// With the shadow on, a rule the other engine answers differently is
// counted under its ID, and the verdict stays the engine in force's, for
// either engine in force.
func TestShadowCountsADisagreementAndKeepsTheVerdict(t *testing.T) {
	for _, inForce := range []string{"go", "re2"} {
		restore := SetRegexForTest(inForce, true)
		resetShadowForTest()
		// XSS-001 matches <script>; its RE2 form is replaced by one that
		// never matches, so the two engines disagree on this input.
		var target Rule
		for _, cr := range blockRules {
			for _, rule := range cr.Rules {
				if rule.ID == "XSS-001" {
					target = rule
				}
			}
		}
		m := *compiledRE2.Load()
		copyM := make(map[*regexp.Regexp]ruleRE2, len(m))
		for k, v := range m {
			copyM[k] = v
		}
		copyM[target.Pattern] = ruleRE2{re: re2.MustCompile(`\A\z never`), id: "XSS-001"}
		compiledRE2.Store(&copyM)

		got := matchRule(target.Pattern, "<script>alert(1)</script>", func() string { return "<script>alert(1)</script>" })
		want := inForce == "go" // Go matches; the forced RE2 form does not
		checks, byRule := ShadowStats()
		if got != want || checks != 1 || len(byRule) != 1 || byRule[0] != (ShadowRuleCount{Rule: "XSS-001", Count: 1}) {
			t.Errorf("%s in force: verdict %v (want %v), checks %d, disagreements %v", inForce, got, want, checks, byRule)
		}
		restore()
	}
	resetShadowForTest()
}

// The same answer is a check and not a disagreement; without the shadow
// nothing is counted.
func TestShadowAgreementAndOff(t *testing.T) {
	restore := SetRegexForTest("go", true)
	resetShadowForTest()
	e := New(Config{BlockThreshold: 10})
	e.MatchRulesScored("<script>alert(1)</script> and ' or 1=1 --")
	checks, byRule := ShadowStats()
	if checks == 0 || len(byRule) != 0 {
		t.Errorf("shadow on, engines agree: checks %d, disagreements %v", checks, byRule)
	}
	restore()

	restore = SetRegexForTest("go", false)
	resetShadowForTest()
	e.MatchRulesScored("<script>alert(1)</script>")
	if checks, _ := ShadowStats(); checks != 0 {
		t.Errorf("shadow off: %d checks", checks)
	}
	restore()
}

// The log is capped at shadowLogsPerMinute lines a minute; the counters are not.
func TestShadowLogIsCapped(t *testing.T) {
	resetShadowForTest()
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	allowed := 0
	for i := 0; i < 50; i++ {
		if shadowLogAllowed(t0.Add(time.Duration(i) * time.Second)) {
			allowed++
		}
	}
	if allowed != shadowLogsPerMinute || !shadowLogAllowed(t0.Add(61*time.Second)) {
		t.Errorf("%d lines allowed in a minute, want %d, and one more after it", allowed, shadowLogsPerMinute)
	}
	resetShadowForTest()
}
