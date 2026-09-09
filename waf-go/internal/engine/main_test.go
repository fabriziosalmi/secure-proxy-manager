package engine

import (
	"os"
	"testing"
)

// testEngine is a default engine shared by the tests that only read from it —
// rule matching and category checks. Tests that need different settings build
// their own with New: that is the point of the type, and the reason the block
// threshold is no longer a package var one test can leave changed for the next
// (SECURE-ARCH-03). Do not mutate testEngine.
var testEngine *Engine

func TestMain(m *testing.M) {
	// The pre-filter is derived from the loaded rule set, exactly as the WAF
	// does at startup; without it the gate is absent and every rule is scanned.
	BuildPrefilter()
	testEngine = New(Config{})
	os.Exit(m.Run())
}
