package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// dnsmasq holds every blacklisted domain in memory: measured 195 MiB per
// million against the dns container's 256 MiB, and the aggregated public list
// (5.5 million) got it OOM-killed, which takes DNS away from the proxy. Every
// path that adds domains stops at SPM_DNS_BLOCKLIST_MAX_DOMAINS.
func TestDomainBlacklistLimitOnEveryPath(t *testing.T) {
	t.Setenv("SPM_DNS_BLOCKLIST_MAX_DOMAINS", "3")
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewBlacklistHandlers(db, cfg)
	count := func() int {
		var n int
		_ = db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&n)
		return n
	}

	// Import that would exceed the limit: refused whole.
	body, _ := json.Marshal(map[string]string{"type": "domain", "content": "a.example\nb.example\nc.example\nd.example"})
	w := httptest.NewRecorder()
	h.Import(w, httptest.NewRequest("POST", "/api/blacklists/import", bytes.NewReader(body)))
	if w.Code != http.StatusRequestEntityTooLarge || count() != 0 {
		t.Fatalf("an import past the limit: status %d, %d rows stored (want 413, 0)", w.Code, count())
	}
	if !strings.Contains(w.Body.String(), "SPM_DNS_BLOCKLIST_MAX_DOMAINS") {
		t.Errorf("the refusal does not say which limit: %s", w.Body.String())
	}

	// Import within the limit: accepted.
	body, _ = json.Marshal(map[string]string{"type": "domain", "content": "a.example\nb.example\nc.example"})
	w = httptest.NewRecorder()
	h.Import(w, httptest.NewRequest("POST", "/api/blacklists/import", bytes.NewReader(body)))
	if w.Code != http.StatusOK || count() != 3 {
		t.Fatalf("an import up to the limit: status %d, %d rows (want 200, 3)", w.Code, count())
	}

	// Single add at the limit: refused.
	body, _ = json.Marshal(map[string]string{"domain": "e.example"})
	w = httptest.NewRecorder()
	h.AddDomain(w, httptest.NewRequest("POST", "/api/domain-blacklist", bytes.NewReader(body)))
	if w.Code != http.StatusRequestEntityTooLarge || count() != 3 {
		t.Errorf("an add at the limit: status %d, %d rows (want 413, 3)", w.Code, count())
	}

	// IP imports are not limited by it.
	body, _ = json.Marshal(map[string]string{"type": "ip", "content": "203.0.113.1\n203.0.113.2\n203.0.113.3\n203.0.113.4"})
	w = httptest.NewRecorder()
	h.Import(w, httptest.NewRequest("POST", "/api/blacklists/import", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Errorf("an IP import was refused by the domain limit: %d", w.Code)
	}
}

func TestRestoreStopsAtTheDomainLimit(t *testing.T) {
	t.Setenv("SPM_DNS_BLOCKLIST_MAX_DOMAINS", "2")
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	entries := []map[string]string{}
	for i := 0; i < 5; i++ {
		entries = append(entries, map[string]string{"value": fmt.Sprintf("r%d.example", i)})
	}
	b, _ := json.Marshal(map[string]any{"backup_version": 2, "settings": map[string]string{}, "lists": map[string]any{"domain_blacklist": entries}})
	w := httptest.NewRecorder()
	NewMaintenanceHandlers(db, cfg).RestoreConfig(w, httptest.NewRequest("POST", "/api/maintenance/restore-config", bytes.NewReader(b)))
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&n)
	if w.Code != http.StatusOK || n != 2 {
		t.Errorf("restore of 5 domains with a limit of 2: status %d, %d stored", w.Code, n)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["skipped_entries"] != float64(3) {
		t.Errorf("skipped_entries = %v, want 3", resp["skipped_entries"])
	}
}
