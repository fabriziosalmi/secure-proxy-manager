package workers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every line below was written by Squid 7.7 from the proxy image, behind the
// real WAF image and a real dnsmasq with a blacklisted name, and copied from
// access.log unchanged (docs/design/block-reasons.md, "Measurements").
// Lines in the new spm logformat (13 fields):
const (
	lineAllowed         = "1792921939.100      4 192.168.88.50 TCP_MISS/200 255 GET http://pub.test/ - HIER_DIRECT/192.168.88.20 text/html - none -"
	lineDomainBL        = "1792921939.358      0 192.168.88.50 TCP_DENIED/403 4860 GET http://bl.test/ - HIER_NONE/- text/html - domain_blacklist -"
	lineSinkholeGET     = "1792921939.620      0 192.168.88.50 TCP_DENIED/403 4862 GET http://sink.test/ - HIER_NONE/- text/html - domain_blacklist_dns -"
	lineIPBL            = "1792921939.898      0 192.168.88.50 TCP_DENIED/403 4862 GET http://ipbl.test/ - HIER_NONE/- text/html - ip_blacklist -"
	lineContent         = "1792921940.156      0 192.168.88.50 TCP_DENIED/403 4866 GET http://pub.test/x.exe - HIER_NONE/- text/html - content_filter -"
	lineDirectIP        = "1792921940.664      0 192.168.88.50 TCP_DENIED/403 4860 GET http://8.8.8.8/ - HIER_NONE/- text/html - direct_ip -"
	lineWAF             = "1792921940.930      1 192.168.88.50 NONE_NONE/403 205 GET http://pub.test/? - HIER_NONE/- text/html dmdts8y4qdl2-3 none waf"
	lineOrigin404       = "1792921941.209      1 192.168.88.50 TCP_MISS/404 689 GET http://pub.test/nope - HIER_DIRECT/192.168.88.20 text/html - none -"
	linePort            = "1792921941.440      0 192.168.88.50 TCP_DENIED/403 4864 GET http://pub.test:21/ - HIER_NONE/- text/html - port_policy -"
	lineMethod          = "1792921941.717      0 192.168.88.50 TCP_DENIED/403 4861 PUT http://pub.test/ - HIER_NONE/- text/html - protocol_policy -"
	lineSinkholeCONNECT = "1792921942.002      0 192.168.88.50 TCP_DENIED/403 4864 CONNECT sink.test:443 - HIER_NONE/- text/html - domain_blacklist_dns -"
	lineConnectPort     = "1792921942.252      0 192.168.88.50 TCP_DENIED/403 4856 CONNECT pub.test:22 - HIER_NONE/- text/html - port_policy -"
	lineConnectDirectIP = "1792921942.753      0 192.168.88.50 TCP_DENIED/403 4862 CONNECT 8.8.8.8:443 - HIER_NONE/- text/html - direct_ip -"
	lineAuthNoCreds     = "1792921961.882      0 192.168.88.50 TCP_DENIED/407 3381 GET http://pub.test/ - HIER_NONE/- text/html - proxy_auth -"
	lineAuthWrongCreds  = "1792921962.151     16 192.168.88.50 TCP_DENIED/407 3381 GET http://pub.test/ u1 HIER_NONE/- text/html - proxy_auth -"
	lineAuthOK          = "1792921962.411      6 192.168.88.50 TCP_MISS/200 255 GET http://pub.test/ u1 HIER_DIRECT/192.168.88.20 text/html - none -"
	lineAuthWAF         = "1792921962.918      0 192.168.88.50 NONE_NONE/403 205 GET http://pub.test/? u1 HIER_NONE/- text/html dmdtsj1rx5ow-7 none waf"
	lineTime            = "1792921966.851      0 192.168.88.50 TCP_DENIED/403 4861 GET http://pub.test/ - HIER_NONE/- text/html - time_restriction -"
	lineRespmodWAF      = "1792921995.846      2 192.168.88.50 TCP_MISS/403 189 GET http://dl.test/a - HIER_DIRECT/192.168.88.22 text/html - none waf"
	lineOrigin403       = "1792922424.877     10 192.168.88.50 TCP_MISS/403 233 GET http://o403.test/ - HIER_DIRECT/192.168.88.24 text/plain - none -"
	lineICAPDown        = "1792922067.397   3058 192.168.88.50 NONE_NONE/500 3377 GET http://pub.test/ - HIER_NONE/- text/html - none -"
	// SSL-bump on: a denied CONNECT is logged twice, the CONNECT (TCP_DENIED/200,
	// with the reason) and the error page served inside the bumped tunnel
	// (NONE_NONE/403, no note). This pair is what made a Squid deny and a WAF
	// block look the same on the test deployment.
	lineBumpDeniedConnect = "1792921999.249      5 192.168.88.50 TCP_DENIED/200 0 CONNECT bl.test:443 - HIER_NONE/- - - domain_blacklist -"
	lineBumpErrorPage     = "1792921999.249      0 192.168.88.50 NONE_NONE/403 4857 GET https://bl.test/ - HIER_NONE/- text/html - - -"
	lineBumpSinkConnect   = "1792921999.536      3 192.168.88.50 TCP_DENIED/200 0 CONNECT sink.test:443 - HIER_NONE/- - - domain_blacklist_dns -"
	lineBumpConnect       = "1792922046.430      3 192.168.88.50 NONE_NONE/200 0 CONNECT tls.test:443 - HIER_DIRECT/192.168.88.23 - - none -"
	lineBumpWAF           = "1792922046.431      0 192.168.88.50 NONE_NONE/403 205 GET https://tls.test/? - HIER_NONE/- text/html dmdttlexjzfi-i none waf"
)

// Lines the origin/main config wrote for the same requests (11 fields, no
// reason). The two 503s are the DNS sinkhole: dnsmasq answered 0.0.0.0 and ::
// and Squid tried to connect to :: (HIER_DIRECT/::). That is the deployment's
// "TCP_TUNNEL/503 with blocked=0".
const (
	oldAllowed        = "1792922091.426      5 192.168.88.50 TCP_MISS/200 255 GET http://pub.test/ - HIER_DIRECT/192.168.88.20 text/html -"
	oldDomainBL       = "1792922091.747      0 192.168.88.50 TCP_DENIED/403 4860 GET http://bl.test/ - HIER_NONE/- text/html -"
	oldSinkholeGET    = "1792922092.078      1 192.168.88.50 TCP_MISS_ABORTED/503 4889 GET http://sink.test/ - HIER_DIRECT/:: text/html -"
	oldWAF            = "1792922092.471      0 192.168.88.50 NONE_NONE/403 205 GET http://pub.test/? - HIER_NONE/- text/html dmdtu6kcnqzd-3"
	oldSinkholeTunnel = "1792922092.747      0 192.168.88.50 TCP_TUNNEL/503 0 CONNECT sink.test:443 - HIER_DIRECT/:: - -"
)

func TestParseSquidLineRecordsTheRuleThatMatched(t *testing.T) {
	cases := []struct {
		name, line, reason string
		blocked            int
	}{
		{"allowed", lineAllowed, ReasonNone, 0},
		{"domain blacklist (Squid ACL)", lineDomainBL, ReasonDomainBlacklist, 1},
		{"sinkholed name, GET", lineSinkholeGET, ReasonDomainBlacklistDNS, 1},
		{"sinkholed name, CONNECT", lineSinkholeCONNECT, ReasonDomainBlacklistDNS, 1},
		{"IP blacklist", lineIPBL, ReasonIPBlacklist, 1},
		{"content filter", lineContent, ReasonContentFilter, 1},
		{"direct IP, GET", lineDirectIP, ReasonDirectIP, 1},
		{"direct IP, CONNECT", lineConnectDirectIP, ReasonDirectIP, 1},
		{"WAF REQMOD block", lineWAF, ReasonWAF, 1},
		{"WAF RESPMOD block", lineRespmodWAF, ReasonWAF, 1},
		{"origin 404", lineOrigin404, ReasonNone, 0},
		{"origin 403 is not a block", lineOrigin403, ReasonNone, 0},
		{"port policy, GET", linePort, ReasonPortPolicy, 1},
		{"port policy, CONNECT", lineConnectPort, ReasonPortPolicy, 1},
		{"method policy", lineMethod, ReasonProtocolPolicy, 1},
		{"proxy auth, no credentials", lineAuthNoCreds, ReasonProxyAuth, 1},
		{"proxy auth, wrong credentials", lineAuthWrongCreds, ReasonProxyAuth, 1},
		{"proxy auth passed: the note was reset", lineAuthOK, ReasonNone, 0},
		{"proxy auth passed, then the WAF", lineAuthWAF, ReasonWAF, 1},
		{"time restriction", lineTime, ReasonTimeRestriction, 1},
		{"WAF unreachable (fail closed) is an error, not a block", lineICAPDown, ReasonNone, 0},
		{"SSL-bump: the denied CONNECT carries the reason", lineBumpDeniedConnect, ReasonDomainBlacklist, 1},
		{"SSL-bump: the error page inside the tunnel is not a second block", lineBumpErrorPage, ReasonNone, 0},
		{"SSL-bump: sinkholed CONNECT", lineBumpSinkConnect, ReasonDomainBlacklistDNS, 1},
		{"SSL-bump: allowed CONNECT", lineBumpConnect, ReasonNone, 0},
		{"SSL-bump: WAF block inside the tunnel", lineBumpWAF, ReasonWAF, 1},

		// Lines without the reason fields: no reason is invented, except where
		// the sinkhole address itself shows what happened.
		{"old format: allowed", oldAllowed, ReasonUnclassified, 0},
		{"old format: deny keeps the status heuristic", oldDomainBL, ReasonUnclassified, 1},
		{"old format: WAF keeps the status heuristic", oldWAF, ReasonUnclassified, 1},
		{"old format: GET to the sinkhole address", oldSinkholeGET, ReasonDomainBlacklistDNS, 1},
		{"old format: CONNECT to the sinkhole address", oldSinkholeTunnel, ReasonDomainBlacklistDNS, 1},
	}
	for _, c := range cases {
		got := parseSquidLine(c.line)
		if got == nil {
			t.Errorf("%s: line did not parse", c.name)
			continue
		}
		if got["reason"] != c.reason || got["blocked"] != c.blocked {
			t.Errorf("%s: reason=%v blocked=%v, want reason=%s blocked=%d", c.name, got["reason"], got["blocked"], c.reason, c.blocked)
		}
	}
}

// The WAF event id is still read from its own field when the reason fields
// follow it.
func TestParseSquidLineKeepsTheWAFEventID(t *testing.T) {
	if got := parseSquidLine(lineWAF); got["event_id"] != "dmdts8y4qdl2-3" {
		t.Errorf("event_id = %v", got["event_id"])
	}
	if got := parseSquidLine(lineDomainBL); got["event_id"] != "" {
		t.Errorf("event_id of a Squid deny = %v, want empty", got["event_id"])
	}
}

// A note this backend did not write (an operator's own annotate_transaction in
// custom extras) is stored as other, never as the raw string.
func TestParseSquidLineUnknownNoteIsOther(t *testing.T) {
	line := strings.Replace(lineDomainBL, "domain_blacklist", "my_custom_rule", 1)
	if got := parseSquidLine(line); got["reason"] != ReasonOther || got["blocked"] != 1 {
		t.Errorf("unknown note: %v / %v, want other / 1", got["reason"], got["blocked"])
	}
}

// The tailer stores what it parsed: the real lines go through tailOnce into
// proxy_logs, and the stored reason and flag are the parsed ones.
func TestTailerStoresTheBlockReason(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	lines := []string{lineAllowed, lineSinkholeGET, lineWAF, lineOrigin403, lineBumpDeniedConnect, lineBumpErrorPage, oldWAF}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := tailOnce(db, nil, logPath, 0, squidTail); !ok {
		t.Fatal("tailOnce committed nothing")
	}
	rows, err := db.Query(`SELECT block_reason, blocked FROM proxy_logs ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var r string
		var b int
		_ = rows.Scan(&r, &b)
		got = append(got, r+"/"+string(rune('0'+b)))
	}
	want := []string{"none/0", "domain_blacklist_dns/1", "waf/1", "none/0", "domain_blacklist/1", "none/0", "unclassified/1"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("stored %v\nwant   %v", got, want)
	}
}

// dnsmasq log lines as the dns image writes them for one Squid lookup of a
// blacklisted name (captured from the same run).
const dnsLookup = `Oct 25 09:52:19 dnsmasq[1]: query[A] sink.test from 192.168.88.10
Oct 25 09:52:19 dnsmasq[1]: /config/dnsmasq.d/blocklist.hosts sink.test is 0.0.0.0
Oct 25 09:52:19 dnsmasq[1]: query[AAAA] sink.test from 192.168.88.10
Oct 25 09:52:19 dnsmasq[1]: /config/dnsmasq.d/blocklist.hosts sink.test is ::`

// One lookup is one row, not two (A and AAAA), and it is marked as a
// resolver row with its reason. A later lookup of the same name is a row again.
func TestDNSTailerStoresOneRowPerLookup(t *testing.T) {
	dnsAnswers = &dnsDedupe{seen: map[string]time.Time{}}
	var entries []map[string]any
	later := strings.ReplaceAll(dnsLookup, "09:52:19", "09:52:31")
	for _, l := range strings.Split(dnsLookup+"\n"+later, "\n") {
		if e := parseDNSLine(l); e != nil {
			entries = append(entries, e)
		}
	}
	if len(entries) != 2 {
		t.Fatalf("got %d rows for two lookups (each A+AAAA), want 2", len(entries))
	}
	for _, e := range entries {
		if e["method"] != "DNS" || e["reason"] != ReasonDomainBlacklistDNS || e["source_ip"] != "192.168.88.10" || e["destination"] != "sink.test" {
			t.Errorf("row %v", e)
		}
	}
}

func TestSyslogTime(t *testing.T) {
	a, ok1 := syslogTime("Oct  5 09:52:19 dnsmasq[1]: x")
	b, ok2 := syslogTime("Oct  5 09:52:20 dnsmasq[1]: x")
	if !ok1 || !ok2 || b.Sub(a) != time.Second {
		t.Errorf("syslogTime: %v %v %v %v", a, ok1, b, ok2)
	}
	if _, ok := syslogTime("short"); ok {
		t.Error("a short line has no time")
	}
}
