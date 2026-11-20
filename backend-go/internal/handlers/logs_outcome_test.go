package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A request no rule blocked that ended in 502, 503 or 504 failed beyond the
// proxy: the UI shows it as "Upstream error", and outcome=allowed listed it
// with the requests that worked. The three outcomes now split the log: every
// row is in exactly one of them, as the badge says, the list and the count
// agree, and the rows left out as internal are counted per outcome too.
func TestLogsOutcomeSplitsUpstreamErrorsFromAllowed(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	now := time.Now()
	row := func(src, dest string, status any, blocked int, reason string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, blocked, block_reason)
			VALUES(?, ?, ?, 'CONNECT', ?, ?, 0, ?, ?)`,
			now.UTC().Format("2006-01-02 15:04:05"), now.Unix(), src, dest, status, blocked, reason); err != nil {
			t.Fatal(err)
		}
	}
	// Allowed: worked, or failed at the server with another code.
	row(lanClient, "ok.test:443", "TCP_TUNNEL/200", 0, "none")
	row(lanClient, "missing.test/x", "TCP_MISS/404", 0, "none")
	row(lanClient, "nostatus.test:443", nil, 0, "none")
	// A DNS answer carries an address, not a code: one ending in 503 is not a 503.
	row(lanClient, "v6.test", "2001:db8::503", 0, "none")
	// Upstream errors.
	row(lanClient, "gone.test:443", "TCP_TUNNEL/503", 0, "none")
	row(lanClient, "broken.test/", "TCP_MISS/502", 0, "none")
	row(lanClient, "slow.test/", "TCP_MISS/504", 0, "none")
	// Blocked, whatever the code: a blocked /503 is blocked.
	row(lanClient, "ads.test:443", "TCP_DENIED/403", 1, "domain_blacklist")
	row(lanClient, "sinkholed.test:443", "TCP_TUNNEL/503", 1, "domain_blacklist_dns_reconstructed")
	// The Docker host's own traffic, left out by default: one upstream error, one allowed.
	row(hostGateway, "feed.test:443", "TCP_TUNNEL/503", 0, "none")
	row(hostGateway, "feed.test:443", "TCP_TUNNEL/200", 0, "none")

	h := NewLogHandlers(db).WithSources(composeSources(t, db))
	dests := func(p logsPage) map[string]bool {
		out := map[string]bool{}
		for _, r := range p.Data {
			out[r.Destination] = true
		}
		return out
	}
	want := map[string]struct {
		dests    []string
		internal int
	}{
		"allowed":        {[]string{"ok.test:443", "missing.test/x", "nostatus.test:443", "v6.test"}, 1},
		"upstream_error": {[]string{"gone.test:443", "broken.test/", "slow.test/"}, 1},
		"blocked":        {[]string{"ads.test:443", "sinkholed.test:443"}, 0},
	}
	seen := map[string]string{}
	for outcome, w := range want {
		p, code := getLogs(t, h, "limit=100&outcome="+outcome)
		if code != http.StatusOK {
			t.Fatalf("outcome=%s: status %d", outcome, code)
		}
		got := dests(p)
		if len(got) != len(w.dests) || len(p.Data) != len(w.dests) {
			t.Errorf("outcome=%s: rows %v, want %v", outcome, got, w.dests)
		}
		for _, d := range w.dests {
			if !got[d] {
				t.Errorf("outcome=%s: %s missing, got %v", outcome, d, got)
			}
		}
		if p.Meta.Total != len(p.Data) {
			t.Errorf("outcome=%s: meta.total %d, %d rows listed", outcome, p.Meta.Total, len(p.Data))
		}
		if p.Meta.Internal == nil || *p.Meta.Internal != w.internal {
			t.Errorf("outcome=%s: meta.internal %v, want %d", outcome, p.Meta.Internal, w.internal)
		}
		for d := range got {
			if prev, dup := seen[d]; dup {
				t.Errorf("%s is in outcome=%s and outcome=%s", d, prev, outcome)
			}
			seen[d] = outcome
		}
	}
	all, _ := getLogs(t, h, "limit=100")
	if len(seen) != all.Meta.Total || all.Meta.Total != 9 {
		t.Errorf("the three outcomes hold %d rows, the unfiltered log %d (want 9)", len(seen), all.Meta.Total)
	}

	// The export selects the same rows.
	_, recs := readExport(t, h, "outcome=upstream_error")
	if len(recs)-1 != 3 {
		t.Errorf("export outcome=upstream_error: %d rows, want 3", len(recs)-1)
	}
}

// The refusal names every value outcome takes.
func TestLogsOutcomeRefusalNamesUpstreamError(t *testing.T) {
	h, cleanup := filterFixture(t)
	defer cleanup()
	r := httptest.NewRequest("GET", "/api/logs?outcome=denied", nil)
	w := httptest.NewRecorder()
	h.GetLogs(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
	for _, v := range []string{"allowed", "upstream_error", "blocked"} {
		if !strings.Contains(w.Body.String(), v) {
			t.Errorf("refusal %q does not name %s", w.Body.String(), v)
		}
	}
}
