package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	appMW "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

type coverageResp struct {
	Data struct {
		Domain struct {
			Entries  *int             `json:"entries"`
			SquidACL *DomainACLStatus `json:"squid_acl"`
		} `json:"domain_blacklist"`
		IP struct {
			Entries  *int         `json:"entries"`
			SquidACL *IPACLStatus `json:"squid_acl"`
		} `json:"ip_blacklist"`
		WAF   wafCoverage `json:"waf"`
		HTTPS *bool       `json:"https_inspection"`
		Login *bool       `json:"proxy_login"`
		Alert struct {
			Enabled      *bool `json:"enabled"`
			Channels     *int  `json:"channels"`
			WAFDelivered *bool `json:"waf_alerts_delivered"`
		} `json:"alerts"`
	} `json:"data"`
}

func freshWAFBreaker(t *testing.T) {
	t.Helper()
	wafBreaker = appMW.NewCircuitBreaker(3, 30*time.Second)
	t.Cleanup(func() { wafBreaker = appMW.NewCircuitBreaker(3, 30*time.Second) })
}

func intIs(p *int, n int) bool    { return p != nil && *p == n }
func boolIs(p *bool, b bool) bool { return p != nil && *p == b }

// val is what p points to, or nil, for a failure message.
func val[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

// A fresh install: empty lists, everything off, no WAF answering.
func TestCoverageOfAFreshInstall(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	freshWAFBreaker(t)
	cfg.WAFURL = "http://127.0.0.1:1"
	var resp coverageResp
	getJSON(t, NewAnalyticsHandlers(db, cfg).Coverage, "/api/analytics/coverage", &resp)
	d := resp.Data
	if d.IP.SquidACL != nil {
		t.Errorf("ip squid_acl = %+v without a record, want null", d.IP.SquidACL)
	}
	if !intIs(d.Domain.Entries, 0) || d.Domain.SquidACL != nil || !intIs(d.IP.Entries, 0) {
		t.Errorf("lists: domain %v (squid %v), ip %v; want 0, null, 0", val(d.Domain.Entries), d.Domain.SquidACL, val(d.IP.Entries))
	}
	if !boolIs(d.HTTPS, false) || !boolIs(d.Login, false) {
		t.Errorf("https_inspection %v, proxy_login %v; want false, false", val(d.HTTPS), val(d.Login))
	}
	if !boolIs(d.Alert.Enabled, false) || !intIs(d.Alert.Channels, 0) || !boolIs(d.Alert.WAFDelivered, false) {
		t.Errorf("alerts = enabled %v, channels %v, waf %v; want off, 0 channels, WAF alerts not delivered", val(d.Alert.Enabled), val(d.Alert.Channels), val(d.Alert.WAFDelivered))
	}
	if d.WAF.Status != "unreachable" || d.WAF.Rules != nil || d.WAF.Categories != nil {
		t.Errorf("waf = %+v; want unreachable with no counts", d.WAF)
	}
}

// Every line reports the deployment's own state: the tables, the proxy's
// record, the settings, the alert plan and the WAF's rule count.
func TestCoverageReportsWhatIsSwitchedOn(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	freshWAFBreaker(t)
	for _, d := range []string{"a.test", "b.test"} {
		if _, err := db.Exec("INSERT INTO domain_blacklist(domain) VALUES(?)", d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("INSERT INTO ip_blacklist(ip) VALUES('192.0.2.1')"); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"ssl_bump_enabled": "true", "enable_proxy_auth": "true", "enable_notifications": "true",
		"webhook_url": "https://hooks.example/x",
		// A Telegram token without a chat is not a channel.
		"telegram_bot_token": "123:abc",
	} {
		if _, err := db.Exec("INSERT OR REPLACE INTO settings(setting_name, setting_value) VALUES(?, ?)", k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cfg.ConfigDir, "ip_blacklist_acl_status.json"), []byte(`{"version":1,"entries":1,"networks":1,"dropped":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.ConfigDir, domainACLStatusFile), []byte(`{"version":1,"names":2,"limit":100000,"held":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.AlertToken = "svc-token"
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/categories" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":[{"name":"sqli","rules":100,"enabled":true},{"name":"xss","rules":72,"enabled":false}]}`))
	}))
	defer waf.Close()
	cfg.WAFURL = waf.URL

	var resp coverageResp
	getJSON(t, NewAnalyticsHandlers(db, cfg).Coverage, "/api/analytics/coverage", &resp)
	d := resp.Data
	if !intIs(d.Domain.Entries, 2) || !intIs(d.IP.Entries, 1) {
		t.Errorf("entries: domain %v, ip %v; want 2 and 1", val(d.Domain.Entries), val(d.IP.Entries))
	}
	if d.IP.SquidACL == nil || d.IP.SquidACL.Networks != 1 {
		t.Errorf("ip squid_acl = %+v; want the proxy record, 1 network", d.IP.SquidACL)
	}
	if d.Domain.SquidACL == nil || !d.Domain.SquidACL.Held || d.Domain.SquidACL.Names != 2 {
		t.Errorf("squid_acl = %+v; want held with 2 names", d.Domain.SquidACL)
	}
	if !boolIs(d.HTTPS, true) || !boolIs(d.Login, true) {
		t.Errorf("https_inspection %v, proxy_login %v; want true, true", val(d.HTTPS), val(d.Login))
	}
	if !boolIs(d.Alert.Enabled, true) || !intIs(d.Alert.Channels, 1) || !boolIs(d.Alert.WAFDelivered, true) {
		t.Errorf("alerts = enabled %v, channels %v, waf %v; want on, 1 channel, delivered", val(d.Alert.Enabled), val(d.Alert.Channels), val(d.Alert.WAFDelivered))
	}
	if d.WAF.Status != "ok" || !intIs(d.WAF.Categories, 2) || !intIs(d.WAF.CategoriesEnabled, 1) || !intIs(d.WAF.Rules, 172) || !intIs(d.WAF.RulesEnabled, 100) {
		t.Errorf("waf = %s, %v categories (%v on), %v rules (%v on); want ok, 2 categories (1 on), 172 rules (100 on)", d.WAF.Status, val(d.WAF.Categories), val(d.WAF.CategoriesEnabled), val(d.WAF.Rules), val(d.WAF.RulesEnabled))
	}
}

func TestCoverageSaysWhyTheWAFHasNoRuleCount(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		want   string
	}{
		{http.StatusForbidden, "", "auth_failed"},
		{http.StatusUnauthorized, "", "auth_failed"},
		{http.StatusInternalServerError, "", "error"},
		{http.StatusOK, `not json`, "error"},
	} {
		t.Run(c.want+"/"+http.StatusText(c.status), func(t *testing.T) {
			db, _, cfg, cleanup := setupTestDB(t)
			defer cleanup()
			freshWAFBreaker(t)
			waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer waf.Close()
			cfg.WAFURL = waf.URL
			var resp coverageResp
			getJSON(t, NewAnalyticsHandlers(db, cfg).Coverage, "/api/analytics/coverage", &resp)
			if w := resp.Data.WAF; w.Status != c.want || w.Rules != nil || w.RulesEnabled != nil {
				t.Errorf("waf = %+v; want %s with no counts", w, c.want)
			}
		})
	}
}
