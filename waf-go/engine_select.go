package main

import (
	"fmt"
	"log/slog"
	"strings"

	"secure-proxy-waf/internal/crs"
	"secure-proxy-waf/internal/engine"
)

// wafEngine is WAF_ENGINE as in force: "hybrid" (the default) or "legacy".
var wafEngine string

// crsEng is the OWASP Core Rule Set half of the hybrid; nil under legacy.
var crsEng *crs.Engine

// newCRS builds the CRS half; a test replaces it to make the load fail.
var newCRS = crs.New

// observeDefaults are the request-rule categories that only observe when
// WAF_OBSERVE_CATEGORIES is empty. The hybrid leaves data leak prevention,
// financial data and cloud secrets to observe: a password, a card number or
// a key in an outgoing body is alerted, not blocked, unless an administrator
// chooses to block it: example and dummy values in pasted code cannot be told
// from real ones. Legacy is the engine as it was.
var observeDefaults = map[string][]string{
	"hybrid": {"DATA_LEAK_PREVENTION", "FINANCIAL_DATA", "CLOUD_SECRETS"},
	"legacy": nil,
}

// selectEngine reads WAF_ENGINE and WAF_OBSERVE_CATEGORIES. An unknown
// engine, or a CRS that does not load, is an error: the WAF does not start
// rather than run an engine the operator did not choose.
func selectEngine(getenv func(string) string) (name string, c *crs.Engine, observe []string, err error) {
	name = strings.ToLower(strings.TrimSpace(getenv("WAF_ENGINE")))
	if name == "" {
		name = "hybrid"
	}
	defaults, ok := observeDefaults[name]
	if !ok {
		return "", nil, nil, fmt.Errorf("WAF_ENGINE=%q: want hybrid or legacy", getenv("WAF_ENGINE"))
	}
	if name == "hybrid" {
		if c, err = newCRS(crs.Options{Paranoia: 1}); err != nil {
			return "", nil, nil, err
		}
	}
	observe = defaults
	switch raw := strings.TrimSpace(getenv("WAF_OBSERVE_CATEGORIES")); strings.ToLower(raw) {
	case "":
	case "none":
		observe = nil
	default:
		observe = nil
		for _, cat := range strings.Split(raw, ",") {
			if cat = strings.TrimSpace(cat); cat != "" {
				observe = append(observe, cat)
			}
		}
	}
	return name, c, observe, nil
}

// warnUnknownCategories names the categories in a list that no request rule
// carries: a misspelt observe-only category goes on blocking.
func warnUnknownCategories(variable string, cats []string) {
	known := map[string]bool{}
	for _, cr := range engine.BlockRules() {
		known[cr.Category] = true
	}
	for _, cat := range cats {
		if !known[cat] {
			slog.Warn("unknown WAF category", "variable", variable, "category", cat)
		}
	}
}
