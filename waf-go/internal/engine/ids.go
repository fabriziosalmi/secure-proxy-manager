package engine

// signalIDs are the rule IDs a request can be reported under that are not
// regex rules: the heuristics, the domain reputation checks and the body
// size signal. TestSignalIDsCoverTheSource holds the list to the code.
var signalIDs = map[string]bool{
	"H1-ENTROPY": true, "H1-URL-ENTROPY": true, "H2-BEACON": true, "H3-PII": true,
	"H4-SHARDING": true, "H6-GHOST": true, "H7-SEQUENCE": true,
	"ML-DGA-001": true, "ML-TYPO-001": true, "WAF-BODY-OVERSIZE": true,
}

// KnownRuleID reports whether id is a rule the WAF can report: a request
// rule, custom rules included, or one of the signals. The policy uses it so
// that an exception for a misspelt rule is an error rather than a no-op.
func KnownRuleID(id string) bool {
	if signalIDs[id] {
		return true
	}
	for _, cr := range blockRules {
		for _, r := range cr.Rules {
			if r.ID == id {
				return true
			}
		}
	}
	return false
}
