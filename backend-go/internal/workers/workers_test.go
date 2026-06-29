package workers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/websocket"
)

func setupTestDB(t *testing.T) (*sql.DB, func()) {
	tmpDir := t.TempDir()
	tmpDB := filepath.Join(tmpDir, "test.db")
	db, err := database.Open(tmpDB)
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}

	adminPass := "admin-12345"
	adminHash, _ := auth.HashPassword(adminPass)
	if err := database.Init(db, "admin", adminHash); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}

	cleanup := func() {
		db.Close()
	}

	return db, cleanup
}

func TestRunRetention(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Seed some logs
	_, _ = db.Exec("INSERT INTO proxy_logs (timestamp) VALUES (?)", "2020-01-01 00:00:00")
	_, _ = db.Exec("INSERT INTO settings (setting_name, setting_value) VALUES (?, ?)", "log_retention_days", "30")

	runRetention(db)

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM proxy_logs").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 logs after retention, got %d", count)
	}
}

func TestInsertBlacklistEntries(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Routable IPs are inserted; the private 10.0.0.1 and the invalid line are
	// dropped (the ip_blacklist is a source ACL).
	added := insertBlacklistEntries(db, "ip_blacklist", "ip",
		"1.1.1.1\n2.2.2.2\n10.0.0.1\n# comment\nnotanip", map[string]struct{}{})
	if added != 2 {
		t.Errorf("expected 2 inserted (bogon/invalid dropped), got %d", added)
	}
	var priv int
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist WHERE ip='10.0.0.1'").Scan(&priv)
	if priv != 0 {
		t.Error("private 10.0.0.1 must not enter the source IP blacklist")
	}
}

func TestRefreshList_RefusesLoopback(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "8.8.8.8")
	}))
	defer ts.Close()

	// ts.URL is 127.0.0.1 — the SSRF guard must refuse it and insert nothing.
	refreshList(db, "ip_blacklist", "ip", []string{ts.URL})
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 (loopback refused by SSRF guard), got %d", count)
	}
}

func TestReadRefreshSettings(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	_, _ = db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES (?, ?)", "auto_refresh_enabled", "true")
	_, _ = db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES (?, ?)", "auto_refresh_hours", "24")

	enabled, interval := readRefreshSettings(db)
	if !enabled || interval != 24 {
		t.Errorf("Expected true/24, got %v/%d", enabled, interval)
	}
}

func TestSemverGreater(t *testing.T) {
	cases := []struct {
		v1, v2 string
		want   bool
	}{
		{"1.0.1", "1.0.0", true},
		{"1.0.0", "1.0.1", false},
		{"1.0.0", "1.0.0", false},
		{"2.0.0", "1.9.9", true},
		{"1.0", "1.0.0", false},
	}
	for _, c := range cases {
		if got := semverGreater(c.v1, c.v2); got != c.want {
			t.Errorf("semverGreater(%s, %s) = %v; want %v", c.v1, c.v2, got, c.want)
		}
	}
}

func TestCheckUpdate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"tag_name": "v9.9.9", "html_url": "http://github"}`)
	}))
	defer ts.Close()

	check(ts.URL)
	info := GetUpdateInfo()
	if !info.Available || info.Latest != "v9.9.9" {
		t.Errorf("Expected update available, got %v", info)
	}

	// Failure case (not 200)
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts2.Close()
	check(ts2.URL)

	// Failure case (invalid JSON)
	ts3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "invalid")
	}))
	defer ts3.Close()
	check(ts3.URL)
}

func TestInsertLogBatch(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	batch := []map[string]any{
		{
			"timestamp":      "2024-04-02T10:00:00Z",
			"unix_timestamp": int64(1712052000),
			"source_ip":      "192.168.1.1",
			"method":         "GET",
			"destination":    "http://example.com",
			"status":         "TCP_MISS/200",
			"bytes":          1024,
			"elapsed_ms":     12,
		},
		{"source_ip": "1.2.3.4"}, // partial map — must not break the batch
	}
	if err := insertLogBatch(db, batch); err != nil {
		t.Fatalf("insertLogBatch: %v", err)
	}

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM proxy_logs").Scan(&count)
	if count != 2 {
		t.Errorf("Expected 2 log entries, got %d", count)
	}
	// unix_timestamp must now be populated (the index depends on it).
	var withUnix int
	_ = db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE unix_timestamp = 1712052000").Scan(&withUnix)
	if withUnix != 1 {
		t.Errorf("Expected unix_timestamp to be populated, got %d rows", withUnix)
	}

	// Empty batch is a no-op.
	if err := insertLogBatch(db, nil); err != nil {
		t.Errorf("insertLogBatch(nil): %v", err)
	}
}

func TestLogOffsetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/access.log"
	if got := readOffset(logPath); got != 0 {
		t.Errorf("readOffset with no file = %d, want 0", got)
	}
	writeOffset(logPath, 4096)
	if got := readOffset(logPath); got != 4096 {
		t.Errorf("readOffset after write = %d, want 4096", got)
	}
}

func TestParseSquidLine(t *testing.T) {
	cases := []struct {
		line  string
		valid bool
	}{
		{"1234567890.123    100 127.0.0.1 TCP_MISS/200 1024 GET http://example.com - DIRECT/93.184.216.34 text/html", true},
		{"invalid line", false},
		{"short line 1 2 3", false},
	}
	for _, c := range cases {
		got := parseSquidLine(c.line)
		if (got != nil) != c.valid {
			t.Errorf("parseSquidLine(%s) = %v; want valid=%v", c.line, got, c.valid)
		}
	}
}

func TestParseSquidLine_Edge(t *testing.T) {
	if parseSquidLine("invalid") != nil {
		t.Error("Expected nil for invalid line")
	}
}

func TestIsBlockedStatus(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{"TCP_DENIED/403", true},
		{"TCP_MISS/200", false},
		{"NONE/403", true},
		{"TCP_MISS/403", true},
		{"TCP_DENIED/407", true}, // DENIED action without 403
		{"TCP_TUNNEL/200", false},
		{"NONE_BLOCKED/000", true},
		{"TCP_HIT/304", false},
		{"tcp_denied/000", true}, // case-insensitive, matches the SQL LIKE backfill
		{"x_blocked/000", true},
	}
	for _, c := range cases {
		if got := isBlockedStatus(c.status); got != c.want {
			t.Errorf("isBlockedStatus(%q) = %v; want %v", c.status, got, c.want)
		}
	}
}

func TestParseSquidLine_Blocked(t *testing.T) {
	blockedLine := "1234567890.123 100 127.0.0.1 TCP_DENIED/403 0 GET http://evil.com - HIER_NONE/- text/html"
	got := parseSquidLine(blockedLine)
	if got == nil {
		t.Fatal("expected a parsed map for a blocked line")
	}
	if got["blocked"] != 1 {
		t.Errorf("blocked = %v; want 1", got["blocked"])
	}

	allowedLine := "1234567890.123 100 127.0.0.1 TCP_MISS/200 1024 GET http://example.com - DIRECT/93.184.216.34 text/html"
	got = parseSquidLine(allowedLine)
	if got["blocked"] != 0 {
		t.Errorf("blocked = %v; want 0", got["blocked"])
	}
}

func TestParseSquidVersion_More(t *testing.T) {
	if parseSquidVersion("invalid") != "" {
		t.Error("Expected empty for invalid")
	}
	if parseSquidVersion("Squid Cache: Version 6.1") != "6.1" {
		t.Errorf("Expected 6.1, got %s", parseSquidVersion("Squid Cache: Version 6.1"))
	}
}

func TestRunCheck(t *testing.T) {
	// Test version 5.x
	runCheck("5.7")
	info := GetCVEInfo()
	if info.Version != "5.7" || len(info.CVEs) == 0 {
		t.Errorf("Expected CVEs for 5.7, got %d", len(info.CVEs))
	}

	// Test version 3.x
	runCheck("3.5")
	info = GetCVEInfo()
	if len(info.CVEs) != 2 { // knownCVEs["3."] has 2 items
		t.Errorf("Expected 2 CVEs for 3.5, got %d", len(info.CVEs))
	}

	// Test unknown version
	runCheck("9.9")
	info = GetCVEInfo()
	if len(info.CVEs) != 0 {
		t.Errorf("Expected 0 CVEs for 9.9, got %d", len(info.CVEs))
	}
}

func TestInsertBlacklistEntries_Domain(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Domain lists are not CIDR/bogon-filtered; hosts-format lines take the last
	// field. 0.0.0.0 example.com -> example.com.
	added := insertBlacklistEntries(db, "domain_blacklist", "domain",
		"0.0.0.0 evil.example\nbad.test\n# comment", map[string]struct{}{})
	if added != 2 {
		t.Errorf("expected 2 domains inserted, got %d", added)
	}
}

func TestStartWorkers_Basic(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	tmpDir := t.TempDir()
	hub := websocket.NewHub()

	// These start goroutines that we can't easily wait for, but running them once
	// will increase cover of the startup lines.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartLogRetention(ctx, db)
	StartBlacklistRefresh(ctx, db, tmpDir)
	StartUpdateChecker(ctx, "v1.0.0")

	logFile := filepath.Join(tmpDir, "access.log")
	StartLogTailer(ctx, db, logFile, tmpDir, hub)

	time.Sleep(100 * time.Millisecond)
}

func TestParseDNSLine(t *testing.T) {
	// Parse query line
	queryLine := "Jun 28 08:34:10 dnsmasq[123]: query[A] evil.com from 192.168.1.5"
	entry := parseDNSLine(queryLine)
	if entry != nil {
		t.Fatal("expected parseDNSLine to return nil for queries (side effect only)")
	}

	// Parse reply line
	replyLine := "Jun 28 08:34:10 dnsmasq[123]: config evil.com is 0.0.0.0"
	entry = parseDNSLine(replyLine)
	if entry == nil {
		t.Fatal("expected entry to be parsed for block reply")
	}
	if entry["client_ip"] != "192.168.1.5" {
		t.Errorf("expected client_ip 192.168.1.5, got %v", entry["client_ip"])
	}
	if entry["destination"] != "evil.com" {
		t.Errorf("expected destination evil.com, got %v", entry["destination"])
	}
	if entry["blocked"] != 1 {
		t.Errorf("expected blocked 1, got %v", entry["blocked"])
	}
	if entry["status"] != "DNS_SINKHOLE/0.0.0.0" {
		t.Errorf("expected status DNS_SINKHOLE/0.0.0.0, got %v", entry["status"])
	}
}

func TestStartDNSTailer(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	tmpDir := t.TempDir()
	hub := websocket.NewHub()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logFile := filepath.Join(tmpDir, "dnsmasq.log")
	_ = os.WriteFile(logFile, []byte("Jun 28 08:34:10 dnsmasq[123]: query[A] bad.com from 192.168.1.10\nJun 28 08:34:10 dnsmasq[123]: config bad.com is 0.0.0.0\n"), 0644)
	StartDNSTailer(ctx, db, logFile, tmpDir, hub)

	time.Sleep(800 * time.Millisecond)

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE method='DNS'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 DNS sinkhole log, got %d", count)
	}
}

func TestBoundedDNSCache(t *testing.T) {
	now := time.Now()

	// Roundtrip within TTL.
	c := newBoundedDNSCache(4, time.Minute)
	c.set("evil.com", "192.168.1.5", now)
	if ip, ok := c.get("evil.com", now); !ok || ip != "192.168.1.5" {
		t.Fatalf("expected hit 192.168.1.5, got %q ok=%v", ip, ok)
	}

	// Expiry: a read past the TTL misses and drops the entry.
	if _, ok := c.get("evil.com", now.Add(2*time.Minute)); ok {
		t.Fatal("expected expired entry to miss")
	}
	if c.len() != 0 {
		t.Fatalf("expected expired entry to be evicted on read, len=%d", c.len())
	}

	// Hard cap: inserting well past max never grows the map beyond max.
	small := newBoundedDNSCache(8, time.Hour)
	for i := 0; i < 1000; i++ {
		small.set(fmt.Sprintf("d%d.example", i), "10.0.0.1", now)
		if small.len() > 8 {
			t.Fatalf("cache exceeded cap: len=%d", small.len())
		}
	}
	if small.len() == 0 || small.len() > 8 {
		t.Fatalf("expected 1..8 entries after churn, got %d", small.len())
	}
}
