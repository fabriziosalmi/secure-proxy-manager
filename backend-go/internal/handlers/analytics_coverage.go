package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// wafCoverage is what the WAF reports about its rules, from GET /categories,
// and what it runs, from GET /health. The counts are nil unless status is
// "ok": a WAF that did not answer has no rule count, which is not zero rules.
// CategoriesObserved and RulesObserved count the enabled categories that
// only log their matches and never score them.
type wafCoverage struct {
	Status             string      `json:"status"`
	Categories         *int        `json:"categories"`
	CategoriesEnabled  *int        `json:"categories_enabled"`
	CategoriesObserved *int        `json:"categories_observed"`
	Rules              *int        `json:"rules"`
	RulesEnabled       *int        `json:"rules_enabled"`
	RulesObserved      *int        `json:"rules_observed"`
	Running            *wafRunning `json:"running"`
}

// wafRunning is what the WAF's GET /health says it runs: the engine ("hybrid"
// adds the OWASP Core Rule Set), the score at which it blocks a request, the
// regex engine and whether a second one checks it, how many heuristics are on,
// and the policy's mode ("block", or "observe" for Log only), its number of
// exceptions and whether its last reload failed. PolicyMode is empty when
// the WAF predates the policy.
type wafRunning struct {
	Engine             string `json:"engine"`
	Threshold          int    `json:"threshold"`
	RegexEngine        string `json:"regex_engine"`
	RegexShadow        bool   `json:"regex_shadow"`
	Heuristics         int    `json:"heuristics"`
	PolicyMode         string `json:"policy_mode"`
	PolicyExceptions   int    `json:"policy_exceptions"`
	PolicyReloadFailed bool   `json:"policy_reload_failed"`
}

// wafRunningConfig reads the WAF's GET /health; nil when it did not answer
// with an engine and a threshold.
func wafRunningConfig(r *http.Request, cfg *config.Config) *wafRunning {
	resp, err := wafGetBreaker(r.Context(), cfg, "/health")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var body struct {
		Engine      string `json:"engine"`
		RegexEngine string `json:"regex_engine"`
		RegexShadow bool   `json:"regex_shadow"`
		Threshold   int    `json:"threshold"`
		Heuristics  int    `json:"heuristics"`
		Policy      struct {
			Mode         string `json:"mode"`
			Exceptions   int    `json:"exceptions"`
			ReloadFailed bool   `json:"reload_failed"`
		} `json:"policy"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body) != nil || body.Engine == "" || body.Threshold <= 0 {
		return nil
	}
	return &wafRunning{
		Engine: body.Engine, Threshold: body.Threshold, RegexEngine: body.RegexEngine, RegexShadow: body.RegexShadow,
		Heuristics: body.Heuristics, PolicyMode: body.Policy.Mode, PolicyExceptions: body.Policy.Exceptions,
		PolicyReloadFailed: body.Policy.ReloadFailed,
	}
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
			Observe bool `json:"observe"`
		} `json:"data"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body) != nil || body.Data == nil {
		return wafCoverage{Status: "error"}
	}
	var cats, catsOn, catsObs, rules, rulesOn, rulesObs int
	for _, c := range body.Data {
		cats++
		rules += c.Rules
		if c.Enabled {
			catsOn++
			rulesOn += c.Rules
			if c.Observe {
				catsObs++
				rulesObs += c.Rules
			}
		}
	}
	return wafCoverage{
		Status: "ok", Categories: &cats, CategoriesEnabled: &catsOn, CategoriesObserved: &catsObs,
		Rules: &rules, RulesEnabled: &rulesOn, RulesObserved: &rulesObs, Running: wafRunningConfig(r, h.cfg),
	}
}

// WAFStatus answers GET /api/waf/status: the WAF's rules and what it runs,
// as the coverage reports them, for the pages that show the WAF's state.
func (h *AnalyticsHandlers) WAFStatus(w http.ResponseWriter, r *http.Request) {
	writeOK(w, h.wafRuleCoverage(r))
}

// countOrNil is a COUNT(*) of query, nil when it fails: a count that could
// not be read is not zero.
func (h *AnalyticsHandlers) countOrNil(query database.SQLText) *int {
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
		"ip_blacklist": map[string]any{
			"entries": h.countOrNil("SELECT COUNT(*) FROM ip_blacklist"),
			// What Squid loaded, as the proxy recorded it (#426); null when it has not.
			"squid_acl": nullable(readIPACLStatus(h.cfg.ConfigDir, "ip_blacklist_acl_status.json")),
		},
		"waf":              h.wafRuleCoverage(r),
		"https_inspection": flag("ssl_bump_enabled"),
		"proxy_login":      flag("enable_proxy_auth"),
		// What the proxy did with it, as it recorded it; null when it has not.
		"proxy_login_status": nullable(readProxyAuthStatus(h.cfg.ConfigDir)),
		"alerts":             alerts,
	})
}
