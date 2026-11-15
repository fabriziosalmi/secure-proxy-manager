package handlers

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// on_blocklist on a top destination is what the proxy enforces: the blocklist
// is applied to the exact name (EnforcedDomain: lower case, a leading "*." or
// "." dropped), and a name on the allowed list is not blocked. It carries over
// the status of the retired GET /api/domains/statistics, whose handler once
// loaded the whole blocklist into memory every 30 seconds, compared it with the
// raw destination (a URL or host:port, so it rarely matched), and treated "*.x"
// as covering every name that merely ends in x.
func TestTopDestinationsSayWhatTheBlocklistEnforces(t *testing.T) {
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
			Host        string `json:"host"`
			OnBlocklist *bool  `json:"on_blocklist"`
		} `json:"data"`
	}
	getJSON(t, NewAnalyticsHandlers(db, cfg).TopDestinations, "/api/analytics/top-destinations", &resp)
	got := map[string]bool{}
	for _, d := range resp.Data {
		if d.OnBlocklist == nil {
			t.Fatalf("%s has no on_blocklist", d.Host)
		}
		got[d.Host] = *d.OnBlocklist
	}
	want := map[string]bool{
		"example.com":     true,
		"api.example.com": false,
		"notexample.com":  false,
		"mixed.test":      true,
		"allowed.test":    false,
		"plain.test":      true,
		"unlisted.test":   false,
	}
	if len(got) != len(want) {
		t.Errorf("hosts %v, want the %d of %v", got, len(want), want)
	}
	for host, on := range want {
		if v, ok := got[host]; !ok || v != on {
			t.Errorf("%s: on_blocklist %v (listed %v), want %v", host, v, ok, on)
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
