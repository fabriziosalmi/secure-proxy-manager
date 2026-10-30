package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Every ID literal in the heuristics and the inspection stages is a known
// rule, so a new signal cannot be added without the policy accepting it.
func TestSignalIDsCoverTheSource(t *testing.T) {
	lit := regexp.MustCompile(`\b(?:ID|RuleID):\s+"([A-Za-z0-9_-]+)"`)
	files := []string{"heuristics.go", filepath.Join("..", "inspect", "inspect.go")}
	found := 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range lit.FindAllStringSubmatch(string(src), -1) {
			found++
			if !KnownRuleID(m[1]) {
				t.Errorf("%s: %s is reported but not in signalIDs", f, m[1])
			}
		}
	}
	if found < len(signalIDs) {
		t.Errorf("found %d ID literals, fewer than the %d signals listed", found, len(signalIDs))
	}
	if !KnownRuleID("SQLi-015") || KnownRuleID("SQLi-9999") {
		t.Error("regex rule IDs are not looked up")
	}
}
