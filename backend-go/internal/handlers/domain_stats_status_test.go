package handlers

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// A destination's status on the domain statistics is what the proxy enforces:
// the blocklist is applied to the exact name (EnforcedDomain: lower case, a
// leading "*." or "." dropped), and a name on the allowed list is not blocked.
// The handler used to load the whole blocklist into memory every 30 seconds,
// compare it with the raw destination (a URL or host:port, so it rarely
// matched), and treat "*.x" as covering every name that merely ends in x.
func TestDomainStatsReportsTheStatusTheProxyEnforces(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	for _, d := range []string{"*.example.com", "Mixed.Test", "allowed.test", "plain.test"} {
		if _, err := db.Exec("INSERT INTO domain_blacklist(domain) VALUES(?)", d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("INSERT INTO domain_whitelist(domain) VALUES('allowed.test')"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, dest := range []string{
		"example.com:443",          // listed as *.example.com, enforced as example.com
		"http://api.example.com/x", // a subdomain: not enforced
		"notexample.com:443",       // ends in example.com, is another name
		"mixed.test:443",           // listed with capitals
		"allowed.test:443",         // listed and allowed: the allowed list wins
		"http://plain.test/path",   // listed, reached over plain HTTP
		"unlisted.test:443",
	} {
		insertLogRow(t, db, now, lanClient, "GET", dest, 0, "none")
	}

	var resp struct {
		Data []struct {
			Domain string `json:"domain_name"`
			Status string `json:"status"`
		} `json:"data"`
	}
	getJSON(t, NewAnalyticsHandlers(db, cfg).DomainStats, "/api/domains/statistics", &resp)
	got := map[string]string{}
	for _, d := range resp.Data {
		got[d.Domain] = d.Status
	}
	want := map[string]string{
		"example.com:443":          "Blocked",
		"http://api.example.com/x": "Allowed",
		"notexample.com:443":       "Allowed",
		"mixed.test:443":           "Blocked",
		"allowed.test:443":         "Allowed",
		"http://plain.test/path":   "Blocked",
		"unlisted.test:443":        "Allowed",
	}
	for dest, status := range want {
		if got[dest] != status {
			t.Errorf("%s: status %q, want %q", dest, got[dest], status)
		}
	}
}

// The lookup never scans domain_blacklist itself: the lower-case forms go
// through the UNIQUE index, the mixed-case ones through the partial index that
// holds only them. It replaced a snapshot of the whole table (83.7 MiB for
// 1,000,000 names), and a table scan per page row would trade the memory for
// time.
func TestEnforcedOnBlocklistUsesIndexesOnly(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5000; i++ {
		d := "name" + string(rune('a'+i%26)) + itoaTest(i) + ".test"
		if i%50 == 0 {
			d = "Mixed" + itoaTest(i) + ".Test"
		}
		if _, err := tx.Exec("INSERT INTO domain_blacklist(domain) VALUES(?)", d); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("ANALYZE"); err != nil {
		t.Fatal(err)
	}
	plan := planOf(t, db, enforcedOnBlocklistQuery, "x.test")
	for _, line := range strings.Split(plan, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "SCAN domain_blacklist") && !strings.Contains(l, "INDEX idx_domain_blacklist_mixed_case") {
			t.Errorf("full scan of domain_blacklist in the lookup plan:\n%s", plan)
		}
	}
	if !strings.Contains(plan, "idx_domain_blacklist_mixed_case") {
		t.Errorf("the mixed-case half does not use idx_domain_blacklist_mixed_case:\n%s", plan)
	}
}

func itoaTest(i int) string { return strconv.Itoa(i) }
