package engine

import (
	"regexp"
	"testing"
)

func mustCompileCI(p string) *regexp.Regexp { return regexp.MustCompile("(?i)" + p) }

func TestOverlyBroadRule(t *testing.T) {
	broad := []string{".*", ".+", "", "a?", "(?i).*", "[\\s\\S]*", ".{0,}"}
	ok := []string{"union\\s+select", "<script", "etc/passwd", "\\.\\./"}
	for _, p := range broad {
		re := mustCompileCI(p)
		if reason := overlyBroadRule(re); reason == "" {
			t.Errorf("overlyBroadRule(%q) accepted a catch-all pattern", p)
		}
	}
	for _, p := range ok {
		re := mustCompileCI(p)
		if reason := overlyBroadRule(re); reason != "" {
			t.Errorf("overlyBroadRule(%q) rejected a specific pattern: %s", p, reason)
		}
	}
}
