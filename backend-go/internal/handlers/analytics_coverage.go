package handlers

import (
	"encoding/json"
	"io"
	"net/http"
)

// wafCoverage is what the WAF reports about its rules, from GET /categories.
// The counts are nil unless status is "ok": a WAF that did not answer has no
// rule count, which is not zero rules.
type wafCoverage struct {
	Status            string `json:"status"`
	Categories        *int   `json:"categories"`
	CategoriesEnabled *int   `json:"categories_enabled"`
	Rules             *int   `json:"rules"`
	RulesEnabled      *int   `json:"rules_enabled"`
}

// wafRuleCoverage asks the WAF for its categories. status is "ok",
// "auth_failed" (the WAF refused the backend's credential), "unreachable"
// (no answer, or the circuit is open) or "error" (any other answer), the
// values dashboard/summary uses for waf_status.
func (h *AnalyticsHandlers) wafRuleCoverage(r *http.Request) wafCoverage {
	resp, err := wafGetBreaker(r.Context(), h.cfg, "/categories")
	if err != nil {
		return wafCoverage{Status: "unreachable"}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return wafCoverage{Status: "auth_failed"}
	default:
		return wafCoverage{Status: "error"}
	}
	var body struct {
		Data []struct {
			Rules   int  `json:"rules"`
			Enabled bool `json:"enabled"`
		} `json:"data"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body) != nil || body.Data == nil {
		return wafCoverage{Status: "error"}
	}
	var cats, catsOn, rules, rulesOn int
	for _, c := range body.Data {
		cats++
		rules += c.Rules
		if c.Enabled {
			catsOn++
			rulesOn += c.Rules
		}
	}
	return wafCoverage{Status: "ok", Categories: &cats, CategoriesEnabled: &catsOn, Rules: &rules, RulesEnabled: &rulesOn}
}

// countOrNil is a COUNT(*) of query, nil when it fails: a count that could
// not be read is not zero.
func (h *AnalyticsHandlers) countOrNil(query string) *int {
	n, err := countRows(h.db, query)
	if err != nil {
		return nil
	}
	return &n
}

// Coverage says what protection is switched on now: how many entries each
// blacklist holds and whether Squid holds its own copy of the domain list,
// what the WAF reports about its rules, whether HTTPS inspection and proxy
// login are on, and whether alerts are on and how many channels they go to.
// Each value comes from the setting, the table, the proxy's own record or
// the WAF itself; a value that could not be read is null.
//
// It replaces, on the Analytics page, the security score: a sum of points
// for settings, three of which (enable_ip_blacklist, enable_domain_blacklist,
// enable_waf) nothing reads.
func (h *AnalyticsHandlers) Coverage(w http.ResponseWriter, r *http.Request) {
	settings := map[string]string{}
	settingsRead := false
	if rows, err := h.db.Query(`SELECT setting_name, setting_value FROM settings WHERE setting_name IN ('ssl_bump_enabled', 'enable_proxy_auth')`); err == nil {
		for rows.Next() {
			var k, v string
			if rows.Scan(&k, &v) == nil {
				settings[k] = v
			}
		}
		settingsRead = rows.Err() == nil
		rows.Close()
	}
	flag := func(key string) any {
		if !settingsRead {
			return nil
		}
		return settings[key] == "true"
	}

	// The channels an alert would go to now: the dispatcher's own plan, which
	// does no I/O. Notifications that are off still say how many channels are
	// set up.
	notify, enabled := loadNotificationSettings(h.db, h.cfg.EncryptionKey)
	alerts := map[string]any{"enabled": nil, "channels": nil}
	if notify != nil {
		alerts["enabled"] = enabled
		alerts["channels"] = len(buildDeliveries(notify, map[string]any{}))
	}
	// WAF block alerts reach the backend only with the service token
	// (TestNotification says the same).
	alerts["waf_alerts_delivered"] = h.cfg.AlertToken != ""

	var acl any
	if s := readDomainACLStatus(h.cfg.ConfigDir); s != nil {
		acl = s
	}
	writeOK(w, map[string]any{
		"domain_blacklist": map[string]any{
			"entries":   h.countOrNil("SELECT COUNT(*) FROM domain_blacklist"),
			"squid_acl": acl,
		},
		"ip_blacklist":     map[string]any{"entries": h.countOrNil("SELECT COUNT(*) FROM ip_blacklist")},
		"waf":              h.wafRuleCoverage(r),
		"https_inspection": flag("ssl_bump_enabled"),
		"proxy_login":      flag("enable_proxy_auth"),
		"alerts":           alerts,
	})
}
