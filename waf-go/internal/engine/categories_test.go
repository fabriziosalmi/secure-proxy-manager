package engine

import "testing"

// A disabled category must stop contributing to the score, and re-enabling it
// must bring it back. This is the toggle the mgmt API drives, and until now
// nothing asserted that flipping it changed the verdict rather than only the
// HTTP response: CategoryEnabled could have returned true unconditionally and
// every test still passed.
func TestDisabledCategoryStopsScoring(t *testing.T) {
	const xss = "<script>alert(1)</script>"

	baseline := New(Config{})
	matches, score := baseline.MatchRulesScored(xss)
	if score == 0 || len(matches) == 0 {
		t.Fatalf("the probe payload must score with every category enabled, got %d", score)
	}
	for _, m := range matches {
		if m.Category != "XSS_ATTACKS" {
			t.Fatalf("probe payload also matched %s (%s); it must isolate one category", m.Category, m.RuleID)
		}
	}

	off := New(Config{DisabledCategories: []string{"XSS_ATTACKS"}})
	if _, score := off.MatchRulesScored(xss); score != 0 {
		t.Errorf("XSS_ATTACKS disabled at construction still scored %d", score)
	}
	if off.CategoryEnabled("XSS_ATTACKS") {
		t.Error("CategoryEnabled reports a category disabled at construction as enabled")
	}
	if off.DisabledCategoryCount() != 1 {
		t.Errorf("DisabledCategoryCount = %d, want 1", off.DisabledCategoryCount())
	}

	off.SetCategoryEnabled("XSS_ATTACKS", true)
	if _, score := off.MatchRulesScored(xss); score == 0 {
		t.Error("re-enabling XSS_ATTACKS did not restore its score")
	}

	off.SetCategoryEnabled("XSS_ATTACKS", false)
	if _, score := off.MatchRulesScored(xss); score != 0 {
		t.Error("disabling XSS_ATTACKS at runtime did not stop it scoring")
	}

	// The two engines are independent: the disabled set is per-instance state,
	// not a package var one engine can change for another.
	if _, score := baseline.MatchRulesScored(xss); score == 0 {
		t.Error("toggling one engine's categories changed another engine's verdict")
	}
}

// DisabledCategories feeds the ISTag digest, so it must be ordered.
func TestDisabledCategoriesIsSorted(t *testing.T) {
	e := New(Config{DisabledCategories: []string{"SSRF", "XXE", "LOG4SHELL", "", "XSS_ATTACKS"}})
	got := e.DisabledCategories()
	want := []string{"LOG4SHELL", "SSRF", "XSS_ATTACKS", "XXE"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
