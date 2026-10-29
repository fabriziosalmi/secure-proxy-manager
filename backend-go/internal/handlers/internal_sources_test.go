package handlers

import (
	"database/sql"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/sources"
)

// The test deployment's sources: the backend at 172.18.0.2 on frontend
// (172.18.0.0/16, gateway 172.18.0.1 = the Docker host) and proxy-internal
// (172.19.0.0/16); the proxy at 172.18.0.4.
func composeSources(t *testing.T, db *sql.DB) *InternalSources {
	t.Helper()
	mk := func(cidr string) *net.IPNet {
		ip, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	route := "Iface\tDestination\tGateway \tFlags\n" + "eth0\t00000000\t010012AC\t0003\n"
	snap := sources.NewSnapshot(
		[]net.Addr{mk("127.0.0.1/8"), mk("172.18.0.2/16"), mk("172.19.0.3/16")},
		[]netip.Addr{netip.MustParseAddr("172.18.0.4")},
		[]byte(route),
	)
	return NewInternalSources(db, sources.Fixed(snap))
}

const (
	hostGateway = "172.18.0.1"
	backendIP   = "172.18.0.2"
	// A LAN device in 172.16.0.0/12 that is not on a container subnet.
	lan172 = "172.20.5.9"
)

// seedInternalFixture, all in the last 24 hours unless noted:
//
//	192.168.1.109  5 requests, 2 blocked (1 waf, 1 unclassified from before reasons)
//	172.20.5.9     3 requests, 1 blocked (ip_blacklist)
//	172.18.0.1     4 requests, 2 blocked (domain_blacklist), plus 1 from 30 hours ago
//	172.18.0.2     6 requests
//	127.0.0.1      2 requests
//	172.18.0.4     3 DNS rows (not requests)
func seedInternalFixture(t *testing.T, db *sql.DB) {
	t.Helper()
	now := time.Now()
	for i := 0; i < 5; i++ {
		blocked, reason := 0, "none"
		switch i {
		case 0:
			blocked, reason = 1, "waf"
		case 1:
			blocked, reason = 1, "unclassified"
		}
		insertLogRow(t, db, now, lanClient, "GET", "http://lan.test/", blocked, reason)
	}
	for i := 0; i < 3; i++ {
		blocked, reason := 0, "none"
		if i == 0 {
			blocked, reason = 1, "ip_blacklist"
		}
		insertLogRow(t, db, now, lan172, "GET", "http://lan172.test/", blocked, reason)
	}
	for i := 0; i < 4; i++ {
		blocked, reason := 0, "none"
		if i < 2 {
			blocked, reason = 1, "domain_blacklist"
		}
		insertLogRow(t, db, now, hostGateway, "CONNECT", "host-only.test:443", blocked, reason)
	}
	insertLogRow(t, db, now.Add(-30*time.Hour), hostGateway, "GET", "http://old-host.test/", 1, "domain_blacklist")
	for i := 0; i < 6; i++ {
		insertLogRow(t, db, now, backendIP, "GET", "http://feeds.test/list.txt", 0, "none")
	}
	for i := 0; i < 2; i++ {
		insertLogRow(t, db, now, "127.0.0.1", "GET", "http://loop.test/", 0, "none")
	}
	for i := 0; i < 3; i++ {
		insertLogRow(t, db, now, proxyClient, "DNS", "lan.test", 0, "none")
	}
}

func TestInternalSourcesFindsTheStacksAddressesInTheLog(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	seedInternalFixture(t, db)
	got := composeSources(t, db).Present()
	// 172.18.0.4 has DNS rows only, which are still its rows in the log.
	want := []string{"127.0.0.1", hostGateway, backendIP, proxyClient}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Present() = %v, want %v", got, want)
	}
}

// The lookup reads the source_ip index, not the table.
func TestInternalSourcesLookupUsesTheSourceIndex(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT MIN(source_ip) FROM proxy_logs WHERE source_ip > ? AND source_ip < ?`, "172.18.", "172.18/")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if p := strings.Join(plan, "; "); !strings.Contains(p, "idx_proxy_logs_source_ip") {
		t.Errorf("plan %q does not use idx_proxy_logs_source_ip", p)
	}
}

func TestDashboardLeavesOutInternalSources(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	seedInternalFixture(t, db)
	src := composeSources(t, db)
	h := NewAnalyticsHandlers(db, cfg).WithSources(src)

	var resp struct {
		Data struct {
			Total            int           `json:"total_requests"`
			Blocked          int           `json:"blocked_requests"`
			Today            int           `json:"today_requests"`
			TodayBlocked     int           `json:"today_blocked"`
			Requests         int           `json:"last_24h_requests"`
			DayBlocked       int           `json:"last_24h_blocked"`
			Clients          int           `json:"last_24h_clients"`
			InternalSources  *int          `json:"last_24h_internal_sources"`
			InternalRequests *int          `json:"last_24h_internal_requests"`
			ByReason24h      []reasonCount `json:"blocked_by_reason_24h"`
			ByReason7d       []reasonCount `json:"blocked_by_reason"`
			TopClients       []struct {
				IP    string `json:"ip"`
				Count int    `json:"count"`
			} `json:"top_clients"`
			TopBlocked []topBlockedRow `json:"top_blocked"`
			Recent     []struct {
				Source string `json:"source_ip"`
			} `json:"recent_blocks"`
		} `json:"data"`
	}
	getJSON(t, h.DashboardSummary, "/api/dashboard/summary", &resp)
	d := resp.Data

	// 5 + 3 requests, 2 + 1 blocked, two clients.
	if d.Requests != 8 || d.DayBlocked != 3 || d.Clients != 2 {
		t.Errorf("last 24h: %d requests, %d blocked, %d clients; want 8, 3, 2", d.Requests, d.DayBlocked, d.Clients)
	}
	// The host's request from 30 hours ago is internal too.
	if d.Total != 8 || d.Blocked != 3 {
		t.Errorf("all time: %d requests, %d blocked; want 8 and 3", d.Total, d.Blocked)
	}
	if d.Today > d.Total || d.TodayBlocked > d.Blocked {
		t.Errorf("today %d (blocked %d) exceeds all time %d (blocked %d)", d.Today, d.TodayBlocked, d.Total, d.Blocked)
	}
	// 172.18.0.1, 172.18.0.2 and 127.0.0.1 sent 4 + 6 + 2 requests; the
	// proxy's DNS rows are not requests.
	if d.InternalSources == nil || *d.InternalSources != 3 || d.InternalRequests == nil || *d.InternalRequests != 12 {
		t.Errorf("internal: %v sources, %v requests; want 3 and 12", d.InternalSources, d.InternalRequests)
	}
	if len(d.TopClients) != 2 || d.TopClients[0].IP != lanClient || d.TopClients[1].IP != lan172 {
		t.Errorf("top_clients = %+v; want %s then %s", d.TopClients, lanClient, lan172)
	}
	sum := 0
	for _, r := range d.ByReason24h {
		sum += r.Count
	}
	if sum != d.DayBlocked {
		t.Errorf("blocked_by_reason_24h adds up to %d, last_24h_blocked is %d: %v", sum, d.DayBlocked, d.ByReason24h)
	}
	if countsByReason(d.ByReason7d)["domain_blacklist"] != 0 {
		t.Errorf("blocked_by_reason counts the host's blocks: %v", d.ByReason7d)
	}
	for _, b := range d.TopBlocked {
		if b.Dest == "host-only.test" {
			t.Errorf("top_blocked lists the host's destination: %+v", b)
		}
	}
	for _, b := range d.Recent {
		if b.Source == hostGateway {
			t.Errorf("recent_blocks lists a block of the host: %+v", b)
		}
	}

	// The timeline the Overview draws next to these counts agrees with them.
	lh := NewLogHandlers(db).WithSources(src)
	var tl struct {
		Data []struct {
			Total   int `json:"total"`
			Blocked int `json:"blocked"`
		} `json:"data"`
	}
	getJSON(t, lh.Timeline, "/api/logs/timeline", &tl)
	total, blocked := 0, 0
	for _, e := range tl.Data {
		total += e.Total
		blocked += e.Blocked
	}
	if total != 8 || blocked != 3 {
		t.Errorf("timeline: %d requests, %d blocked; want 8 and 3", total, blocked)
	}
}

func TestClientListMarksInternalSources(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	seedInternalFixture(t, db)
	h := NewAnalyticsHandlers(db, cfg).WithSources(composeSources(t, db))

	var resp struct {
		Data []struct {
			IP       string `json:"ip_address"`
			Requests int    `json:"requests"`
			Blocked  int    `json:"blocked"`
			Internal bool   `json:"internal"`
			Kind     string `json:"kind"`
		} `json:"data"`
		Meta struct {
			Total    int  `json:"total"`
			Internal *int `json:"internal"`
		} `json:"meta"`
	}
	getJSON(t, h.ClientStats, "/api/clients/statistics", &resp)
	if resp.Meta.Total != 2 || resp.Meta.Internal == nil || *resp.Meta.Internal != 3 {
		t.Errorf("meta: total %d, internal %v; want 2 and 3", resp.Meta.Total, resp.Meta.Internal)
	}
	type row struct {
		requests, blocked int
		internal          bool
		kind              string
	}
	want := map[string]row{
		lanClient:   {5, 2, false, sources.KindPrivate},
		lan172:      {3, 1, false, sources.KindPrivate},
		hostGateway: {5, 3, true, sources.KindHost},
		backendIP:   {6, 0, true, sources.KindBackend},
		"127.0.0.1": {2, 0, true, sources.KindLoopback},
	}
	if len(resp.Data) != len(want) {
		t.Fatalf("%d rows, want %d: %+v", len(resp.Data), len(want), resp.Data)
	}
	for i, r := range resp.Data {
		w, ok := want[r.IP]
		if !ok {
			t.Errorf("unexpected row %+v", r)
			continue
		}
		if r.Requests != w.requests || r.Blocked != w.blocked || r.Internal != w.internal || r.Kind != w.kind {
			t.Errorf("%s = %+v; want %+v", r.IP, r, w)
		}
		// The clients come first, then the internal sources.
		if r.Internal != (i >= 2) {
			t.Errorf("row %d (%s) out of order", i, r.IP)
		}
	}

	var det struct {
		Data struct {
			Internal bool   `json:"internal"`
			Kind     string `json:"kind"`
		} `json:"data"`
	}
	r := chi.NewRouter()
	r.Get("/api/clients/{ip}/details", h.ClientDetails)
	getJSON(t, r.ServeHTTP, "/api/clients/"+hostGateway+"/details", &det)
	if !det.Data.Internal || det.Data.Kind != sources.KindHost {
		t.Errorf("details of %s: internal %v, kind %q", hostGateway, det.Data.Internal, det.Data.Kind)
	}
}
