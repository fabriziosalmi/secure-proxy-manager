package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// The test deployment in small. One LAN client (192.168.0.109) and the proxy
// container (172.18.0.4), which resolves names for it through dnsmasq:
//
//   - 9 requests to sinkholed names. Squid logs each as a deny with reason
//     domain_blacklist_dns; dnsmasq logged each lookup twice (A and AAAA) from
//     the proxy, and those rows were what the dashboard counted.
//   - 2 denied by Squid's domain ACL, 1 WAF block, 1 origin 403 (not a block),
//     3 allowed.
//   - 2 rows from before block reasons were recorded (unclassified), one of
//     them blocked by the old heuristic.
//
// Real block count for the client: 9 + 2 + 1 = 12 new, plus 1 legacy.
const (
	lanClient   = "192.168.0.109"
	proxyClient = "172.18.0.4"
)

func seedBlockReasonFixture(t *testing.T, db *sql.DB) {
	t.Helper()
	now := time.Now().UTC()
	ts, unix := now.Format("2006-01-02 15:04:05"), now.Unix()
	ins := func(src, method, dest, status string, blocked int, reason string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, blocked, block_reason)
			VALUES(?, ?, ?, ?, ?, ?, 0, ?, ?)`, ts, unix, src, method, dest, status, blocked, reason); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 9; i++ {
		ins(lanClient, "CONNECT", "sink.test:443", "TCP_DENIED/403", 1, "domain_blacklist_dns")
		ins(proxyClient, "DNS", "sink.test", "DNS_SINKHOLE/0.0.0.0", 1, "domain_blacklist_dns") // A
		ins(proxyClient, "DNS", "sink.test", "DNS_SINKHOLE/0.0.0.0", 1, "domain_blacklist_dns") // AAAA
	}
	ins(lanClient, "GET", "http://bl.test/", "TCP_DENIED/403", 1, "domain_blacklist")
	ins(lanClient, "CONNECT", "bl.test:443", "TCP_DENIED/403", 1, "domain_blacklist")
	ins(lanClient, "GET", "http://pub.test/?", "NONE_NONE/403", 1, "waf")
	ins(lanClient, "GET", "http://o403.test/", "TCP_MISS/403", 0, "none")
	for i := 0; i < 3; i++ {
		ins(lanClient, "GET", "http://pub.test/", "TCP_MISS/200", 0, "none")
	}
	// Legacy rows: the column default, and the flag the old heuristic gave.
	if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, blocked)
		VALUES(?, ?, ?, 'GET', 'http://old.test/', 'NONE_NONE/403', 0, 1), (?, ?, ?, 'CONNECT', 'old.test:443', 'TCP_TUNNEL/503', 0, 0)`,
		ts, unix, lanClient, ts, unix, lanClient); err != nil {
		t.Fatal(err)
	}
}

func getJSON(t *testing.T, h http.HandlerFunc, url string, out any) {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", url, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d", url, w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("%s: %v", url, err)
	}
}

type reasonCount struct {
	Reason string `json:"reason"`
	Label  string `json:"label"`
	Count  int    `json:"count"`
}

func countsByReason(rs []reasonCount) map[string]int {
	m := map[string]int{}
	for _, r := range rs {
		m[r.Reason] = r.Count
	}
	return m
}

func TestDashboardCountsClientRequestsByReason(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	seedBlockReasonFixture(t, db)
	h := NewAnalyticsHandlers(db, cfg)

	var resp struct {
		Data struct {
			Total        int `json:"total_requests"`
			Blocked      int `json:"blocked_requests"`
			TodayTotal   int `json:"today_requests"`
			TodayBlocked int `json:"today_blocked"`
			TopClients   []struct {
				IP    string `json:"ip"`
				Count int    `json:"count"`
			} `json:"top_clients"`
			TopBlocked []struct {
				Dest  string `json:"dest"`
				Count int    `json:"count"`
			} `json:"top_blocked"`
			ByReason []reasonCount `json:"blocked_by_reason"`
			Threats  []struct {
				Category string `json:"category"`
				Count    int    `json:"count"`
			} `json:"threat_categories"`
			Recent []struct {
				Method string `json:"method"`
				Reason string `json:"reason"`
			} `json:"recent_blocks"`
		} `json:"data"`
	}
	getJSON(t, h.DashboardSummary, "/api/dashboard/summary", &resp)
	d := resp.Data

	// 9 + 2 + 1 + 1 + 3 + 2 client rows; 18 DNS rows are not requests.
	if d.Total != 18 || d.TodayTotal != 18 {
		t.Errorf("total = %d, today = %d; want 18 client requests (the 18 DNS rows are lookups, not requests)", d.Total, d.TodayTotal)
	}
	// 12 blocked with a reason + 1 legacy; the origin 403 is not a block.
	if d.Blocked != 13 || d.TodayBlocked != 13 {
		t.Errorf("blocked = %d, today = %d; want 13", d.Blocked, d.TodayBlocked)
	}
	got := countsByReason(d.ByReason)
	want := map[string]int{"domain_blacklist_dns": 9, "domain_blacklist": 2, "waf": 1, "unclassified": 1}
	if len(got) != len(want) {
		t.Errorf("blocked_by_reason = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("blocked_by_reason[%s] = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
	// threat_categories keeps its shape, one entry per reason, by label.
	threats := map[string]int{}
	for _, c := range d.Threats {
		threats[c.Category] = c.Count
	}
	if threats["Domain blacklist (DNS)"] != 9 || threats["WAF"] != 1 || threats["Domain blacklist"] != 2 || threats["Unclassified (no reason recorded)"] != 1 {
		t.Errorf("threat_categories = %v", threats)
	}
	for _, guessed := range []string{"WAF Block", "Direct IP", "Policy", "Malware"} {
		if _, ok := threats[guessed]; ok {
			t.Errorf("threat_categories still has the guessed category %q", guessed)
		}
	}
	for _, c := range d.TopClients {
		if c.IP == proxyClient {
			t.Errorf("the proxy container is listed as a top client (%d requests)", c.Count)
		}
		if c.IP == lanClient && c.Count != 18 {
			t.Errorf("top_clients[%s] = %d, want 18", lanClient, c.Count)
		}
	}
	// The top list groups "sink.test:443" (Squid) and "sink.test" (dnsmasq)
	// under one key; only the 9 client requests may count.
	sinkSeen := false
	for _, b := range d.TopBlocked {
		if b.Dest == "sink.test" || b.Dest == "sink.test:443" {
			sinkSeen = true
			if b.Count != 9 {
				t.Errorf("top_blocked[%s] = %d, want 9 (the 18 DNS rows are not requests)", b.Dest, b.Count)
			}
		}
	}
	if !sinkSeen {
		t.Errorf("top_blocked misses the sinkholed destination: %+v", d.TopBlocked)
	}
	for _, r := range d.Recent {
		if r.Method == "DNS" {
			t.Error("recent_blocks lists a DNS row")
		}
		if r.Reason == "" {
			t.Error("recent_blocks row without a reason")
		}
	}
}

func TestClientStatsAttributeRequestsToTheClient(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	seedBlockReasonFixture(t, db)
	h := NewAnalyticsHandlers(db, cfg)

	var resp struct {
		Data []struct {
			IP       string `json:"ip_address"`
			Requests int    `json:"requests"`
			Blocked  int    `json:"blocked"`
		} `json:"data"`
		Meta ListMeta `json:"meta"`
	}
	getJSON(t, h.ClientStats, "/api/clients/statistics", &resp)
	if resp.Meta.Total != 1 || len(resp.Data) != 1 {
		t.Fatalf("clients = %+v (total %d); want only %s", resp.Data, resp.Meta.Total, lanClient)
	}
	c := resp.Data[0]
	if c.IP != lanClient || c.Requests != 18 || c.Blocked != 13 {
		t.Errorf("client = %+v; want %s with 18 requests, 13 blocked", c, lanClient)
	}

	// The drill-down of the proxy container finds no client requests.
	r := chi.NewRouter()
	r.Get("/api/clients/{ip}/details", h.ClientDetails)
	for _, ip := range []string{proxyClient, lanClient} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/api/clients/"+ip+"/details", nil))
		var det struct {
			Data struct {
				Total    int           `json:"total_requests"`
				Blocked  int           `json:"blocked"`
				ByReason []reasonCount `json:"blocked_by_reason"`
				Recent   []struct {
					Destination string `json:"destination"`
					Status      string `json:"status"`
					Blocked     bool   `json:"blocked"`
					Reason      string `json:"reason"`
					Label       string `json:"reason_label"`
				} `json:"recent"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &det); err != nil {
			t.Fatal(err)
		}
		switch ip {
		case proxyClient:
			if det.Data.Total != 0 || det.Data.Blocked != 0 {
				t.Errorf("proxy container details: %d requests, %d blocked; want 0, 0", det.Data.Total, det.Data.Blocked)
			}
		case lanClient:
			if det.Data.Total != 18 || det.Data.Blocked != 13 || countsByReason(det.Data.ByReason)["domain_blacklist_dns"] != 9 {
				t.Errorf("client details: %d requests, %d blocked, by reason %v", det.Data.Total, det.Data.Blocked, det.Data.ByReason)
			}
			if len(det.Data.Recent) == 0 || det.Data.Recent[0].Reason == "" {
				t.Errorf("recent rows carry no reason: %+v", det.Data.Recent)
			}
			// Each recent request says whether it was blocked, from the row's
			// flag, and names the rule: the origin's own 403 is not a block.
			for _, rr := range det.Data.Recent {
				if rr.Label == "" || rr.Label != workers.ReasonLabel(rr.Reason) {
					t.Errorf("recent %s (%s) is labelled %q", rr.Destination, rr.Reason, rr.Label)
				}
				if rr.Destination == "http://o403.test/" && rr.Blocked {
					t.Errorf("the origin's 403 is reported as blocked: %+v", rr)
				}
				if rr.Reason == "waf" && !rr.Blocked {
					t.Errorf("the WAF block is reported as not blocked: %+v", rr)
				}
			}
		}
	}
}

func TestTimelinesCountClientRequests(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	seedBlockReasonFixture(t, db)

	var traffic struct {
		Data struct {
			Inbound []int `json:"inbound"`
			Blocked []int `json:"blocked"`
		} `json:"data"`
	}
	getJSON(t, NewAnalyticsHandlers(db, cfg).TrafficStats, "/api/traffic/statistics?period=day", &traffic)
	sum := func(xs []int) (n int) {
		for _, x := range xs {
			n += x
		}
		return
	}
	if sum(traffic.Data.Inbound) != 18 || sum(traffic.Data.Blocked) != 13 {
		t.Errorf("traffic: %d requests, %d blocked; want 18, 13", sum(traffic.Data.Inbound), sum(traffic.Data.Blocked))
	}

	lh := NewLogHandlers(db)
	var tl struct {
		Data []struct {
			Total   int `json:"total"`
			Blocked int `json:"blocked"`
		} `json:"data"`
	}
	getJSON(t, lh.Timeline, "/api/logs/timeline", &tl)
	var tt, tb int
	for _, b := range tl.Data {
		tt += b.Total
		tb += b.Blocked
	}
	if tt != 18 || tb != 13 {
		t.Errorf("logs timeline: %d requests, %d blocked; want 18, 13", tt, tb)
	}

	var st struct {
		Data struct {
			Total    int           `json:"total_count"`
			Blocked  int           `json:"blocked_count"`
			IPBlocks int           `json:"ip_blocks_count"`
			ByReason []reasonCount `json:"blocked_by_reason"`
		} `json:"data"`
	}
	getJSON(t, lh.Stats, "/api/logs/stats", &st)
	if st.Data.Total != 18 || st.Data.Blocked != 13 || st.Data.IPBlocks != 0 || countsByReason(st.Data.ByReason)["waf"] != 1 {
		t.Errorf("logs stats = %+v", st.Data)
	}
}

func TestOtherStatisticsLeaveOutTheDNSRows(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	seedBlockReasonFixture(t, db)
	h := NewAnalyticsHandlers(db, cfg)

	var ua struct {
		Data struct {
			Methods []struct {
				Name  string `json:"name"`
				Count int    `json:"count"`
			} `json:"methods"`
		} `json:"data"`
	}
	getJSON(t, h.UserAgents, "/api/analytics/user-agents", &ua)
	for _, m := range ua.Data.Methods {
		if m.Name == "DNS" {
			t.Errorf("user-agents lists DNS as a request method (%d)", m.Count)
		}
	}

	var dom struct {
		Data []struct {
			Name     string `json:"domain_name"`
			Requests int    `json:"requests"`
		} `json:"data"`
	}
	getJSON(t, h.DomainStats, "/api/domains/statistics", &dom)
	for _, d := range dom.Data {
		if d.Name == "sink.test" {
			t.Errorf("domain statistics count the DNS rows as requests to sink.test (%d)", d.Requests)
		}
	}

	var st struct {
		Data struct {
			Count int `json:"requests_count"`
		} `json:"data"`
	}
	getJSON(t, h.Status, "/api/status", &st)
	if st.Data.Count != 18 {
		t.Errorf("status requests_count = %d, want 18", st.Data.Count)
	}
}

// The log list is the log: every row, DNS rows included, each with its reason.
func TestLogListCarriesTheReason(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	seedBlockReasonFixture(t, db)

	var resp struct {
		Data []struct {
			Method  string `json:"method"`
			Status  string `json:"status"`
			Blocked bool   `json:"blocked"`
			Reason  string `json:"reason"`
		} `json:"data"`
		Meta ListMeta `json:"meta"`
	}
	getJSON(t, NewLogHandlers(db).GetLogs, "/api/logs?limit=100", &resp)
	if resp.Meta.Total != 36 || len(resp.Data) != 36 {
		t.Fatalf("listed %d of %d rows; want all 36", len(resp.Data), resp.Meta.Total)
	}
	seen := map[string]int{}
	for _, r := range resp.Data {
		seen[r.Reason]++
		if r.Status == "TCP_MISS/403" && (r.Blocked || r.Reason != "none") {
			t.Errorf("origin 403 listed as blocked=%v reason=%q", r.Blocked, r.Reason)
		}
	}
	if seen["domain_blacklist_dns"] != 27 || seen["unclassified"] != 2 || seen[""] != 0 {
		t.Errorf("reasons listed: %v", seen)
	}
}
