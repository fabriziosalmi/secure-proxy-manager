package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/privacy"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/sources"
	"github.com/go-chi/chi/v5"
)

func setGDPRMode(t *testing.T, db *sql.DB, on bool) {
	t.Helper()
	val := "false"
	if on {
		val = "true"
	}
	if _, err := db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES ('gdpr_mode', ?)", val); err != nil {
		t.Fatalf("set gdpr_mode=%s: %v", val, err)
	}
	privacy.InvalidateDB(db)
}

func assertNoLeakedIPs(t *testing.T, channel, body string, planted []string) {
	t.Helper()
	for _, ip := range planted {
		if strings.Contains(body, ip) {
			t.Errorf("%s leaked full address %q in body:\n%s", channel, ip, body)
		}
	}
}

func TestGDPR_NoFullAddressLeaksInAnyChannel(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	setGDPRMode(t, db, true)

	planted := []string{
		"198.51.100.42",
		"198.51.100.99",
		"203.0.113.7",
		"2001:db8:1:2:3:4:5:6",
		"2001:db8::abcd:1",
	}
	now := time.Now().UTC()
	for _, ip := range planted {
		insertLogRow(t, db, now, ip, "GET", "http://evil.example/path", 1, "domain_blacklist")
	}

	ah := NewAnalyticsHandlers(db, cfg)
	lh := NewLogHandlers(db)
	rtr := chi.NewRouter()
	noopMW := func(next http.Handler) http.Handler { return next }
	ah.Register(rtr, noopMW)
	lh.Register(rtr, noopMW)

	for _, ep := range []struct {
		name string
		path string
	}{
		{"clients/statistics", "/api/clients/statistics"},
		{"clients/details v4", "/api/clients/198.51.100.0%2F24/details"},
		{"clients/details v6", "/api/clients/2001:db8:1:2::%2F64/details"},
		{"dashboard/summary", "/api/dashboard/summary"},
		{"logs", "/api/logs?limit=100"},
		{"logs/export", "/api/logs/export"},
	} {
		req := httptest.NewRequest(http.MethodGet, ep.path, nil)
		rec := httptest.NewRecorder()
		rtr.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s returned status %d: %s", ep.name, rec.Code, rec.Body.String())
		}
		assertNoLeakedIPs(t, ep.name, rec.Body.String(), planted)
		if !strings.Contains(rec.Body.String(), "198.51.100.x") && !strings.Contains(rec.Body.String(), "2001:db8:1:2::x") {
			t.Errorf("%s did not contain masked addresses in body:\n%s", ep.name, rec.Body.String())
		}
	}

	// Verify WAF alerts: formatted message (ntfy), raw webhook JSON, and digest.
	fastNotify(t, 2*time.Second)
	var mu sync.Mutex
	var webhookBodies, ntfyBodies []string
	delivered := make(chan string, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		if strings.HasPrefix(r.URL.Path, "/ntfy/") {
			ntfyBodies = append(ntfyBodies, string(b))
		} else {
			webhookBodies = append(webhookBodies, string(b))
		}
		mu.Unlock()
		delivered <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	for k, v := range map[string]string{
		"enable_notifications":        "true",
		"webhook_url":                 srv.URL + "/hook",
		"ntfy_url":                    srv.URL + "/ntfy/",
		"ntfy_topic":                  "alerts",
		"notify_group_window_minutes": "10",
		"notify_max_per_hour":         "100",
	} {
		_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES(?,?)", k, v)
	}

	clock := now
	var clockMu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := startNotifyQueue(ctx, db, cfg.EncryptionKey, func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}, nil, nil)
	sh := NewSecurityHandlers(db, nil, cfg, q)

	postAlert := func(ip string) {
		payload, _ := json.Marshal(map[string]any{
			"event_type": "waf_block",
			"message":    "WAF blocked request: score 25, categories: SQLI",
			"level":      "error",
			"details": map[string]any{
				"client_ip": ip,
				"category":  "SQLI",
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/internal/alert", bytes.NewReader(payload))
		rec := httptest.NewRecorder()
		sh.ReceiveAlert(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ReceiveAlert status %d: %s", rec.Code, rec.Body.String())
		}
	}

	// First alert goes out immediately; second is held in the group until cancel() flushes the digest.
	postAlert("198.51.100.42")
	postAlert("198.51.100.42")
	postAlert("2001:db8:1:2:3:4:5:6")

	for i := 0; i < 4; i++ {
		select {
		case <-delivered:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for immediate alert deliveries")
		}
	}

	clockMu.Lock()
	clock = clock.Add(11 * time.Minute)
	clockMu.Unlock()
	cancel()
	waitForWorkers(t)

	mu.Lock()
	defer mu.Unlock()
	if len(webhookBodies) < 3 || len(ntfyBodies) < 3 {
		t.Fatalf("expected immediate + digest deliveries; got webhook=%d ntfy=%d", len(webhookBodies), len(ntfyBodies))
	}
	for _, b := range webhookBodies {
		assertNoLeakedIPs(t, "alert webhook", b, planted)
	}
	for _, b := range ntfyBodies {
		assertNoLeakedIPs(t, "alert formatted text", b, planted)
	}
	joinedHooks := strings.Join(webhookBodies, "\n")
	if !strings.Contains(joinedHooks, "198.51.100.x") || !strings.Contains(joinedHooks, "2001:db8:1:2::x") || !strings.Contains(joinedHooks, "waf_block_digest") {
		t.Errorf("webhook bodies missing masked IPs or digest:\n%s", joinedHooks)
	}
}

func TestGDPR_ClientsAggregationAndMixedClassification(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	setGDPRMode(t, db, true)

	// Mark 192.168.50.2 as internal (the backend), while 192.168.50.10 in the same /24 is external.
	src := NewInternalSources(db, sources.Fixed(sources.Snapshot{
		Self: []netip.Addr{netip.MustParseAddr("192.168.50.2")},
	}))
	ah := NewAnalyticsHandlers(db, cfg).WithSources(src)

	base := time.Now().UTC().Add(-1 * time.Hour)
	// Three addresses in 192.168.1.0/24: 2 + 3 + 1 = 6 requests, 1 + 2 + 0 = 3 blocked.
	insertLogRow(t, db, base, "192.168.1.10", "GET", "http://a.test/", 0, "none")
	insertLogRow(t, db, base.Add(time.Minute), "192.168.1.10", "GET", "http://a.test/", 1, "waf")
	insertLogRow(t, db, base.Add(2*time.Minute), "192.168.1.11", "GET", "http://a.test/", 1, "waf")
	insertLogRow(t, db, base.Add(3*time.Minute), "192.168.1.11", "GET", "http://a.test/", 1, "waf")
	insertLogRow(t, db, base.Add(4*time.Minute), "192.168.1.11", "GET", "http://a.test/", 0, "none")
	latest192 := base.Add(5 * time.Minute)
	insertLogRow(t, db, latest192, "192.168.1.12", "GET", "http://a.test/", 0, "none")

	// One address in 10.0.0.0/24: 2 requests, 0 blocked.
	insertLogRow(t, db, base, "10.0.0.5", "GET", "http://b.test/", 0, "none")
	insertLogRow(t, db, base.Add(time.Minute), "10.0.0.5", "GET", "http://b.test/", 0, "none")

	// Mixed network 192.168.50.0/24: one internal (192.168.50.2) and one external (192.168.50.10).
	insertLogRow(t, db, base, "192.168.50.2", "GET", "http://c.test/", 0, "none")
	insertLogRow(t, db, base.Add(time.Minute), "192.168.50.10", "GET", "http://c.test/", 1, "domain_blacklist")

	// Purely internal network 127.0.0.0/24: 127.0.0.1.
	insertLogRow(t, db, base, "127.0.0.1", "GET", "http://local.test/", 0, "none")

	rec := httptest.NewRecorder()
	ah.ClientStats(rec, httptest.NewRequest(http.MethodGet, "/api/clients/statistics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Data []struct {
			IPAddress      string `json:"ip_address"`
			Network        string `json:"network"`
			Addresses      int    `json:"addresses"`
			Requests       int    `json:"requests"`
			Blocked        int    `json:"blocked"`
			LastSeen       string `json:"last_seen"`
			Internal       bool   `json:"internal"`
			Kind           string `json:"kind"`
			Classification string `json:"classification"`
		} `json:"data"`
		Meta ListMeta `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	byNet := map[string]int{}
	for i, row := range resp.Data {
		byNet[row.Network] = i
	}
	for _, wantNet := range []string{"192.168.1.0/24", "10.0.0.0/24", "192.168.50.0/24", "127.0.0.0/24"} {
		if _, ok := byNet[wantNet]; !ok {
			t.Fatalf("missing network %s in %+v", wantNet, resp.Data)
		}
	}

	n192 := resp.Data[byNet["192.168.1.0/24"]]
	if n192.IPAddress != "192.168.1.x" || n192.Addresses != 3 || n192.Requests != 6 || n192.Blocked != 3 || n192.Internal {
		t.Errorf("192.168.1.0/24 = %+v, want ip=192.168.1.x addresses=3 requests=6 blocked=3 internal=false", n192)
	}
	if n192.LastSeen != latest192.Format("2006-01-02 15:04:05") {
		t.Errorf("192.168.1.0/24 last_seen = %q, want %q", n192.LastSeen, latest192.Format("2006-01-02 15:04:05"))
	}

	n10 := resp.Data[byNet["10.0.0.0/24"]]
	if n10.IPAddress != "10.0.0.x" || n10.Addresses != 1 || n10.Requests != 2 || n10.Blocked != 0 || n10.Internal {
		t.Errorf("10.0.0.0/24 = %+v, want ip=10.0.0.x addresses=1 requests=2 blocked=0 internal=false", n10)
	}

	nMixed := resp.Data[byNet["192.168.50.0/24"]]
	if nMixed.Kind != "mixed" || nMixed.Classification != "mixed" || nMixed.Internal || nMixed.Addresses != 2 {
		t.Errorf("192.168.50.0/24 = %+v, want kind=mixed classification=mixed internal=false addresses=2", nMixed)
	}

	nLoop := resp.Data[byNet["127.0.0.0/24"]]
	if !nLoop.Internal || nLoop.Addresses != 1 {
		t.Errorf("127.0.0.0/24 = %+v, want internal=true addresses=1", nLoop)
	}
}

func TestGDPR_DetailsAndLogsFilterByCIDRAndSingleIP400(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	now := time.Now().UTC()
	insertLogRow(t, db, now, "192.168.1.10", "GET", "http://one.test/", 0, "none")
	insertLogRow(t, db, now, "192.168.1.20", "GET", "http://two.test/", 1, "waf")
	insertLogRow(t, db, now, "2001:db8::1", "GET", "http://v6-compressed.test/", 0, "none")
	insertLogRow(t, db, now, "2001:db8:0:0:0:0:0:2", "GET", "http://v6-expanded.test/", 1, "domain_blacklist")

	ah := NewAnalyticsHandlers(db, cfg)
	lh := NewLogHandlers(db)
	rtr := chi.NewRouter()
	noopMW := func(next http.Handler) http.Handler { return next }
	ah.Register(rtr, noopMW)
	lh.Register(rtr, noopMW)

	// 1. With GDPR mode ON:
	setGDPRMode(t, db, true)

	// Single IP must return 400 on details, logs, and CSV export.
	for _, path := range []string{
		"/api/clients/192.168.1.10/details",
		"/api/logs?source_ip=192.168.1.10",
		"/api/logs/export?source_ip=192.168.1.10",
	} {
		rec := httptest.NewRecorder()
		rtr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GDPR on: %s returned %d, want 400", path, rec.Code)
		}
	}

	// CIDR details for IPv4 and compressed IPv6 return 200 for the whole network.
	for _, tc := range []struct {
		path       string
		wantMasked string
		wantNet    string
		wantTotal  int
		wantAddrs  int
	}{
		{"/api/clients/192.168.1.0%2F24/details", "192.168.1.x", "192.168.1.0/24", 2, 2},
		{"/api/clients/192.168.1.0/24/details", "192.168.1.x", "192.168.1.0/24", 2, 2},
		{"/api/clients/2001:db8::%2F64/details", "2001:db8::x", "2001:db8::/64", 2, 2},
	} {
		rec := httptest.NewRecorder()
		rtr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GDPR on: %s status %d: %s", tc.path, rec.Code, rec.Body.String())
		}
		var detail struct {
			Data struct {
				IPAddress     string `json:"ip_address"`
				Network       string `json:"network"`
				Addresses     int    `json:"addresses"`
				TotalRequests int    `json:"total_requests"`
			} `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &detail)
		if detail.Data.IPAddress != tc.wantMasked || detail.Data.Network != tc.wantNet || detail.Data.TotalRequests != tc.wantTotal || detail.Data.Addresses != tc.wantAddrs {
			t.Errorf("%s = %+v, want ip=%s net=%s total=%d addrs=%d", tc.path, detail.Data, tc.wantMasked, tc.wantNet, tc.wantTotal, tc.wantAddrs)
		}
	}

	// CIDR filter on /api/logs and /api/logs/export matches compressed and expanded IPv6 alike.
	for _, cidr := range []string{"192.168.1.0/24", "2001:db8::/64"} {
		p, code := getLogs(t, lh, "source_ip="+cidr)
		if code != http.StatusOK || len(p.Data) != 2 || p.Meta.Total != 2 {
			t.Errorf("GDPR on: logs source_ip=%s: code=%d rows=%d total=%d, want 200, 2, 2", cidr, code, len(p.Data), p.Meta.Total)
		}
		_, recs := readExport(t, lh, "source_ip="+cidr)
		if len(recs)-1 != 2 {
			t.Errorf("GDPR on: export source_ip=%s: %d rows, want 2", cidr, len(recs)-1)
		}
	}

	// 2. With GDPR mode OFF (regression): single IP works as before.
	dbOff, _, cfgOff, cleanupOff := setupTestDB(t)
	defer cleanupOff()
	insertLogRow(t, dbOff, now, "192.168.1.10", "GET", "http://one.test/", 0, "none")
	setGDPRMode(t, dbOff, false)
	ahOff := NewAnalyticsHandlers(dbOff, cfgOff)
	lhOff := NewLogHandlers(dbOff)
	rtrOff := chi.NewRouter()
	ahOff.Register(rtrOff, noopMW)
	lhOff.Register(rtrOff, noopMW)

	rec := httptest.NewRecorder()
	rtrOff.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/clients/192.168.1.10/details", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GDPR off: single IP details returned %d, want 200", rec.Code)
	}
	if p, code := getLogs(t, lhOff, "source_ip=192.168.1.10"); code != http.StatusOK || len(p.Data) != 1 {
		t.Errorf("GDPR off: single IP logs returned code=%d rows=%d, want 200, 1", code, len(p.Data))
	}
}

func TestGDPR_DatabaseExportContainsUnmaskedFlagOnlyWhenOn(t *testing.T) {
	dbOff, _, _, cleanupOff := setupTestDB(t)
	defer cleanupOff()
	insertLogRow(t, dbOff, time.Now().UTC(), "192.168.1.77", "GET", "http://example.com/", 0, "none")
	setGDPRMode(t, dbOff, false)
	recOff := httptest.NewRecorder()
	NewDatabaseHandlers(dbOff).Export(recOff, httptest.NewRequest(http.MethodGet, "/api/database/export", nil))
	var bodyOff map[string]any
	_ = json.Unmarshal(recOff.Body.Bytes(), &bodyOff)
	if _, present := bodyOff["contains_unmasked_addresses"]; present {
		t.Errorf("GDPR off: contains_unmasked_addresses should be absent, got %v", bodyOff["contains_unmasked_addresses"])
	}

	dbOn, _, _, cleanupOn := setupTestDB(t)
	defer cleanupOn()
	insertLogRow(t, dbOn, time.Now().UTC(), "192.168.1.77", "GET", "http://example.com/", 0, "none")
	setGDPRMode(t, dbOn, true)
	recOn := httptest.NewRecorder()
	NewDatabaseHandlers(dbOn).Export(recOn, httptest.NewRequest(http.MethodGet, "/api/database/export", nil))
	var bodyOn map[string]any
	_ = json.Unmarshal(recOn.Body.Bytes(), &bodyOn)
	if bodyOn["contains_unmasked_addresses"] != true {
		t.Errorf("GDPR on: contains_unmasked_addresses = %v, want true", bodyOn["contains_unmasked_addresses"])
	}
	if !strings.Contains(recOn.Body.String(), "192.168.1.77") {
		t.Error("GDPR on: database export must keep full addresses in proxy_logs")
	}
}
