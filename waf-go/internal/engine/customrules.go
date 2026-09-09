package engine

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

// DefaultCustomRulesPath is where the operator's extra patterns are mounted.
const DefaultCustomRulesPath = "/config/waf_custom_rules.txt"

// overlyBroadRule reports a reason string if a compiled custom rule is
// dangerously broad — it matches the empty string, or matches every entry in a
// small benign corpus — which would make it fire on essentially all traffic.
// Returns "" when the rule is acceptably specific.
func overlyBroadRule(re *regexp.Regexp) string {
	if re.MatchString("") {
		return "matches the empty string (would match everything)"
	}
	benign := []string{
		"https://example.com/index.html?lang=en",
		`{"user":"alice","action":"view","id":42}`,
		"GET /assets/app.css HTTP/1.1",
		"the quick brown fox jumps over the lazy dog",
	}
	for _, b := range benign {
		if !re.MatchString(b) {
			return "" // distinguishes at least one benign input → specific enough
		}
	}
	return "matches all benign sample inputs (too broad)"
}

// LoadCustomRules appends the operator's rules from path to the block set. It
// is called once, before the engine is constructed: the rule set is immutable
// for the life of the process.
func LoadCustomRules(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		// Absence is the normal case; unreadable is not, and the two used to
		// produce the same line with the error discarded entirely. /config is a
		// bind-mounted volume and this container runs read-only with dropped
		// capabilities, so a permission or ownership problem is realistic — and
		// it left an operator running with strictly less detection than they
		// configured, told nothing distinguishable from having written no rules
		// (SECURE-ERR-02). Every other failure in this function names the rule
		// and the reason; only the one that disables all of them was anonymous.
		if os.IsNotExist(err) {
			log.Printf("No custom rules file at %s, using default rules only.\n", path)
		} else {
			log.Printf("WARNING: custom rules file %s could not be read (%v) — "+
				"running with DEFAULT RULES ONLY; any custom detections are not loaded\n", path, err)
		}
		return
	}

	lines := strings.Split(string(content), "\n")
	var customRules []Rule

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			if len(line) > 512 {
				log.Printf("Custom rule %d skipped: exceeds 512 char limit\n", i+1)
				continue
			}
			if strings.ContainsRune(line, 0) {
				log.Printf("Custom rule %d skipped: contains null byte\n", i+1)
				continue
			}
			compiled, err := regexp.Compile("(?i)" + line)
			if err != nil {
				log.Printf("Error compiling custom rule %s: %v\n", line, err)
			} else if reason := overlyBroadRule(compiled); reason != "" {
				// A rule that matches everything (".*", "", "a?", …) would score 7
				// on every request → mass false-positive blocks. Reject at load.
				log.Printf("Custom rule %d skipped: %s (pattern %q)\n", i+1, reason, line)
			} else {
				customRules = append(customRules, Rule{
					ID:       fmt.Sprintf("CUSTOM-%03d", i+1),
					Pattern:  compiled,
					Severity: 7,
					Tier:     2,
				})
			}
		}
	}

	if len(customRules) > 0 {
		blockRules = append(blockRules, CategoryRules{
			Category: "CUSTOM_USER_RULES",
			Rules:    customRules,
		})
		log.Printf("Loaded %d custom WAF rules.\n", len(customRules))
	}
}
