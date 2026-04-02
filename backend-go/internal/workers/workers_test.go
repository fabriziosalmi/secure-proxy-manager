package workers

import (
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
	db.Exec("INSERT INTO proxy_logs (timestamp) VALUES (?)", "2020-01-01 00:00:00")
	db.Exec("INSERT INTO settings (setting_name, setting_value) VALUES (?, ?)", "log_retention_days", "30")

	runRetention(db)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM proxy_logs").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 logs after retention, got %d", count)
	}
}

func TestRefreshList(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "1.1.1.1")
		fmt.Fprintln(w, "2.2.2.2")
	}))
	defer ts.Close()

	refreshList(db, "ip_blacklist", "ip", []string{ts.URL})

	var count int
	db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&count)
	if count != 2 {
		t.Errorf("Expected 2 IPs, got %d", count)
	}
}

func TestReadRefreshSettings(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES (?, ?)", "auto_refresh_enabled", "true")
	db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES (?, ?)", "auto_refresh_hours", "24")

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

func TestInsertLogEntry(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// 1. Success
	entry := map[string]any{
		"timestamp":   "2024-04-02T10:00:00Z",
		"source_ip":   "192.168.1.1",
		"method":      "GET",
		"destination": "http://example.com",
		"status":      "TCP_MISS/200",
		"bytes":       1024,
	}
	insertLogEntry(db, entry)

	// 2. Missing fields (coverage for partial maps)
	insertLogEntry(db, map[string]any{"source_ip": "1.2.3.4"})

	var count int
	db.QueryRow("SELECT COUNT(*) FROM proxy_logs").Scan(&count)
	if count != 2 {
		t.Errorf("Expected 2 log entries, got %d", count)
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

func TestRefreshAll(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "10.0.0.1")
	}))
	defer ts.Close()

	// Override default lists to use our mock server
	oldIP := defaultIPLists
	oldDomain := defaultDomainLists
	defaultIPLists = []string{ts.URL}
	defaultDomainLists = []string{ts.URL}
	defer func() {
		defaultIPLists = oldIP
		defaultDomainLists = oldDomain
	}()

	refreshAll(db)

	var ipCount, domainCount int
	db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&ipCount)
	db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&domainCount)
	if ipCount != 1 || domainCount != 1 {
		t.Errorf("Expected counts (1,1), got (%d,%d)", ipCount, domainCount)
	}
}

func TestStartWorkers_Basic(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	tmpDir := t.TempDir()
	hub := websocket.NewHub()

	// These start goroutines that we can't easily wait for, but running them once
	// will increase cover of the startup lines.
	StartLogRetention(db)
	StartBlacklistRefresh(db, tmpDir)
	StartUpdateChecker("v1.0.0")
	
	logFile := filepath.Join(tmpDir, "access.log")
	os.WriteFile(logFile, []byte("test"), 0644)
	StartLogTailer(db, logFile, hub)
	
	time.Sleep(100 * time.Millisecond)
}
