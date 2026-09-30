package handlers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// SECURE-INPT-02. A domain entry is written, one per line, into the dnsmasq
// hosts file. Before, only a space was refused, so a tab or newline planted a
// second record there: an authenticated caller could make the resolver answer
// any name with any address. Reproduced against the unfixed code; these fail
// there.
func TestAddDomainRefusesLineBreakingValues(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewBlacklistHandlers(db, cfg)

	for _, bad := range []string{
		"x.test\n203.0.113.9\tupdate.example.com",
		"x.test\t203.0.113.9",
		"x.test\r\ny.test",
		"x.test\x00",
		"example.com:8080",
		"a..b.test",
	} {
		body, _ := json.Marshal(map[string]string{"domain": bad})
		w := httptest.NewRecorder()
		h.AddDomain(w, httptest.NewRequest("POST", "/api/domain-blacklist", bytes.NewReader(body)))
		if w.Code != 400 {
			t.Errorf("AddDomain(%q) = %d, want 400", bad, w.Code)
		}
	}
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&n)
	if n != 0 {
		t.Errorf("%d rows stored from refused values", n)
	}

	// Legitimate forms still work, including a URL with a port and a wildcard.
	for _, ok := range []string{"good.example.com", "*.wild.example.com", "https://url.example.com:8443/path"} {
		body, _ := json.Marshal(map[string]string{"domain": ok})
		w := httptest.NewRecorder()
		h.AddDomain(w, httptest.NewRequest("POST", "/api/domain-blacklist", bytes.NewReader(body)))
		if w.Code != 200 {
			t.Errorf("AddDomain(%q) = %d, want 200: %s", ok, w.Code, w.Body.String())
		}
	}
	var got string
	_ = db.QueryRow("SELECT domain FROM domain_blacklist WHERE domain LIKE 'url.%'").Scan(&got)
	if got != "url.example.com" {
		t.Errorf("URL form stored %q, want the hostname without the port", got)
	}
}

func TestAddWhitelistAndEgressRefuseLineBreakingValues(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewBlacklistHandlers(db, cfg)

	post := func(fn func(w2 *httptest.ResponseRecorder, body []byte), body map[string]string) int {
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		fn(w, b)
		return w.Code
	}
	wl := func(w *httptest.ResponseRecorder, b []byte) {
		h.AddDomainWhitelist(w, httptest.NewRequest("POST", "/x", bytes.NewReader(b)))
	}
	eg := func(w *httptest.ResponseRecorder, b []byte) {
		h.AddDstAllow(w, httptest.NewRequest("POST", "/x", bytes.NewReader(b)))
	}
	if c := post(wl, map[string]string{"domain": "a.test\tb.test"}); c != 400 {
		t.Errorf("whitelist accepted a tab: %d", c)
	}
	if c := post(eg, map[string]string{"entry": "a.test\nb.test"}); c != 400 {
		t.Errorf("egress allowlist accepted a newline: %d", c)
	}
	if c := post(eg, map[string]string{"entry": "10.1.2.0/24"}); c != 200 {
		t.Errorf("egress allowlist refused a CIDR: %d", c)
	}
}

func TestRestoreSkipsInvalidListEntriesAndCountsThem(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	m := NewMaintenanceHandlers(db, cfg)

	backup := map[string]any{
		"backup_version": 2,
		"settings":       map[string]string{"proxy_port": "3128"},
		"lists": map[string]any{
			"domain_blacklist": []map[string]string{
				{"value": "ok.example.org"},
				{"value": "y.test\n203.0.113.10 evil.example.org"},
			},
			"ip_blacklist": []map[string]string{
				{"value": "203.0.113.7"},
				{"value": "192.168.1.0/24"}, // private: refused by AddIP, so refused here
				{"value": "not-an-ip"},
			},
			"dst_allowlist": []map[string]string{
				{"value": "10.9.0.0/16"},
				{"value": "a.test\tb.test"},
			},
		},
	}
	b, _ := json.Marshal(backup)
	w := httptest.NewRecorder()
	m.RestoreConfig(w, httptest.NewRequest("POST", "/api/maintenance/restore-config", bytes.NewReader(b)))
	if w.Code != 200 {
		t.Fatalf("restore = %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if got := resp["skipped_entries"]; got != float64(4) {
		t.Errorf("skipped_entries = %v, want 4", got)
	}
	for table, want := range map[string]int{"domain_blacklist": 1, "ip_blacklist": 1, "dst_allowlist": 1} {
		var n int
		_ = db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
		if n != want {
			t.Errorf("%s holds %d rows, want %d", table, n, want)
		}
	}
}

// The exporter is the last line: whatever the tables hold, the hosts file gets
// one record per entry.
func TestExportNeverEmitsASecondHostsRecord(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	if _, err := db.Exec("INSERT INTO domain_blacklist(domain) VALUES(?), (?)",
		"good.test", "x.test\n203.0.113.9\tupdate.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := database.ExportBlacklistsToFiles(db, cfg.ConfigDir); err != nil {
		t.Fatal(err)
	}
	hosts, _ := os.ReadFile(filepath.Join(cfg.ConfigDir, "dnsmasq.d", "blocklist.hosts"))
	if strings.Contains(string(hosts), "203.0.113.9") || strings.Contains(string(hosts), "update.example.com") {
		t.Errorf("the hosts file carries an injected record:\n%s", hosts)
	}
	if !strings.Contains(string(hosts), "0.0.0.0 good.test") {
		t.Errorf("the legitimate entry is missing:\n%s", hosts)
	}
	list, _ := os.ReadFile(filepath.Join(cfg.ConfigDir, "domain_blacklist.txt"))
	if strings.Contains(string(list), "203.0.113.9") {
		t.Errorf("the Squid ACL file carries an injected line:\n%s", list)
	}
}
