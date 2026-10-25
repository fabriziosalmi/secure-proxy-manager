package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// planOf returns the EXPLAIN QUERY PLAN details of query, one per line.
func planOf(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	rs, err := db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatalf("explain %q: %v", query, err)
	}
	defer rs.Close()
	var out []string
	for rs.Next() {
		var id, parent, notused int
		var detail string
		if err := rs.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		out = append(out, detail)
	}
	return strings.Join(out, "\n")
}

// logPageQuery is the page query GetLogs runs for f.
func logPageQuery(f logFilter, internal []string) (string, []any) {
	w, a := f.where(internal, true)
	return "SELECT " + logColumns + " FROM proxy_logs WHERE " + w + " ORDER BY id DESC LIMIT ? OFFSET ?", append(a, 100, 0)
}

// countPlans is the plans of the COUNT queries countLogs runs for f.
func countPlans(t *testing.T, db *sql.DB, f logFilter, internal []string) []string {
	t.Helper()
	var out []string
	for _, ct := range f.countTerms(internal) {
		out = append(out, planOf(t, db, ct.query, ct.args...))
	}
	return out
}

// The access log is the largest table and the filters must reach their rows
// through an index, not by reading the table. Each filter that has an index
// to use is checked against the plan SQLite picks: a client by
// idx_proxy_logs_source_ip, a rule by idx_proxy_logs_blocked_reason, blocked
// rows by a partial index on them, the internal sources' rows by the source
// index. A destination substring (LIKE '%x%') has no index that could serve
// it; it walks the table newest first and stops at the page size.
//
// The plans are taken as a deployment gets them: Init runs ANALYZE at every
// start, so the planner knows the shape of the log. The fixture is the 1M
// measurement's, smaller.
func TestLogFiltersUseIndexes(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	seed1M(t, db, 20_000)
	if _, err := db.Exec("ANALYZE"); err != nil {
		t.Fatal(err)
	}
	internal := []string{"172.18.0.1", "172.18.0.2"}

	cases := []struct {
		name  string
		f     logFilter
		count bool
		want  string
	}{
		{"client page", logFilter{sourceIP: "192.168.0.10"}, false, "idx_proxy_logs_source_ip"},
		{"client count", logFilter{sourceIP: "192.168.0.10"}, true, "idx_proxy_logs_source_ip"},
		{"rule page", logFilter{reason: "waf"}, false, "idx_proxy_logs_blocked_reason"},
		{"rule count", logFilter{reason: "waf"}, true, "idx_proxy_logs_blocked_reason"},
		{"blocked page", logFilter{outcome: "blocked", includeInternal: true}, false, "idx_proxy_logs_blocked"},
		{"cursor page", logFilter{includeInternal: true, beforeID: 500}, false, "INTEGER PRIMARY KEY (rowid<?)"},
	}
	for _, c := range cases {
		plans := countPlans(t, db, c.f, internal)
		if !c.count {
			q, a := logPageQuery(c.f, internal)
			plans = []string{planOf(t, db, q, a...)}
		}
		for _, plan := range plans {
			if !strings.Contains(plan, c.want) {
				t.Errorf("%s: plan does not use %s:\n%s", c.name, c.want, plan)
			}
			if strings.Contains(plan, "TEMP B-TREE") {
				t.Errorf("%s: sorted in a temporary b-tree instead of read in index order:\n%s", c.name, plan)
			}
		}
	}

	// The default view leaves the internal sources out. Its counts are every
	// row (any index, read whole) and the internal rows (a range of the source
	// index), never "source_ip NOT IN (...)" over the table.
	plans := countPlans(t, db, logFilter{}, internal)
	if len(plans) != 2 || !strings.Contains(plans[1], "idx_proxy_logs_source_ip (source_ip=?)") {
		t.Errorf("default view counts: want every row, then the internal rows by idx_proxy_logs_source_ip; got\n%s", strings.Join(plans, "\n--\n"))
	}
	// Allowed rows are every row less the blocked ones (the partial index).
	plans = countPlans(t, db, logFilter{outcome: "allowed", includeInternal: true}, internal)
	if len(plans) != 2 || !strings.Contains(plans[1], "idx_proxy_logs_blocked") {
		t.Errorf("allowed counts: want every row, then the blocked rows by a partial index; got\n%s", strings.Join(plans, "\n--\n"))
	}
}

// TestLogFilters1M loads a million rows and prints, for every filter, the
// plans of the page and count queries and how long GET /api/logs takes. It
// measures, it does not judge: run it with SPM_LOGS_1M=1 (and -v).
func TestLogFilters1M(t *testing.T) {
	if os.Getenv("SPM_LOGS_1M") == "" {
		t.Skip("set SPM_LOGS_1M=1 to load the 1M-row fixture and measure")
	}
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	const n = 1_000_000
	start := time.Now()
	seed1M(t, db, n)
	t.Logf("seeded %d rows in %s", n, time.Since(start).Round(time.Millisecond))
	// What the new index costs a deployment that upgrades with a full log:
	// Init creates it once, on start-up.
	if _, err := db.Exec("DROP INDEX idx_proxy_logs_blocked_reason"); err != nil {
		t.Fatal(err)
	}
	created := time.Now()
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_proxy_logs_blocked_reason ON proxy_logs(block_reason) WHERE blocked = 1"); err != nil {
		t.Fatal(err)
	}
	t.Logf("creating idx_proxy_logs_blocked_reason on %d rows took %s", n, time.Since(created).Round(time.Millisecond))
	if _, err := db.Exec("ANALYZE"); err != nil {
		t.Fatal(err)
	}

	h := NewLogHandlers(db).WithSources(composeSources(t, db))
	internal := h.src.Present()
	t.Logf("internal sources present: %v", internal)

	cases := []struct {
		name string
		f    logFilter
		qs   string
	}{
		{"default (internal hidden)", logFilter{}, ""},
		{"include internal", logFilter{includeInternal: true}, "include_internal=true"},
		{"client", logFilter{sourceIP: "192.168.0.15"}, "source_ip=192.168.0.15"},
		{"blocked", logFilter{outcome: "blocked"}, "outcome=blocked"},
		{"allowed", logFilter{outcome: "allowed"}, "outcome=allowed"},
		{"rule waf", logFilter{reason: "waf"}, "reason=waf"},
		{"rule ip_blacklist (rare)", logFilter{reason: "ip_blacklist"}, "reason=ip_blacklist"},
		{"q common", logFilter{q: "host-12"}, "q=host-12"},
		{"q rare", logFilter{q: "host-4999."}, "q=host-4999."},
		{"q absent", logFilter{q: "nothing-matches"}, "q=nothing-matches"},
		{"client + rule", logFilter{sourceIP: "192.168.0.15", reason: "domain_blacklist_dns"}, "source_ip=192.168.0.15&reason=domain_blacklist_dns"},
		{"cursor deep", logFilter{beforeID: 100_000}, "before_id=100000"},
	}
	for _, c := range cases {
		pq, pa := logPageQuery(c.f, internal)
		t.Logf("== %s\n  page:  %s\n  count: %s", c.name,
			strings.ReplaceAll(planOf(t, db, pq, pa...), "\n", " | "),
			strings.ReplaceAll(strings.Join(countPlans(t, db, c.f, internal), " ; "), "\n", " | "))
		var best time.Duration
		for i := 0; i < 3; i++ {
			r := httptest.NewRequest("GET", "/api/logs?limit=100&sort=id&order=desc&"+c.qs, nil)
			w := httptest.NewRecorder()
			t0 := time.Now()
			h.GetLogs(w, r)
			d := time.Since(t0)
			if w.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", c.name, w.Code, w.Body.String())
			}
			if i == 0 || d < best {
				best = d
			}
		}
		t.Logf("  GET /api/logs: best of 3 %s", best.Round(100*time.Microsecond))
	}

	r := httptest.NewRequest("GET", "/api/logs/export?"+url.Values{"reason": {"waf"}}.Encode(), nil)
	w := httptest.NewRecorder()
	t0 := time.Now()
	h.Export(w, r)
	t.Logf("== export reason=waf: %d bytes, %d lines in %s", w.Body.Len(), strings.Count(w.Body.String(), "\n"), time.Since(t0).Round(time.Millisecond))
}

// seed1M writes n rows shaped like a home deployment: 20 LAN devices, the
// backend and the Docker host (internal, about 10% of the rows), about 10%
// blocked over five rules, destinations over 5,000 hosts, one row a second.
func seed1M(t *testing.T, db *sql.DB, n int) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, blocked, block_reason)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Duration(n) * time.Second).Unix()
	for i := 0; i < n; i++ {
		src := fmt.Sprintf("192.168.0.%d", 10+i%20)
		switch i % 20 {
		case 0:
			src = "172.18.0.2"
		case 1:
			src = "172.18.0.1"
		}
		blocked, reason, status := 0, "none", "TCP_TUNNEL/200"
		switch i % 100 {
		case 3, 13, 23, 33, 43:
			blocked, reason, status = 1, "domain_blacklist_dns", "TCP_DENIED/403"
		case 5:
			blocked, reason, status = 1, "waf", "NONE_NONE/403"
		case 7, 17, 27:
			blocked, reason, status = 1, "unclassified", "TCP_DENIED/403"
		case 9:
			blocked, reason, status = 1, "direct_ip", "TCP_DENIED/403"
		}
		if i%1000 == 11 {
			blocked, reason, status = 1, "ip_blacklist", "TCP_DENIED/403"
		}
		ts := base + int64(i)
		dest := fmt.Sprintf("host-%d.example.com:443", i%5000)
		if _, err := stmt.Exec(time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05"), ts, src, "CONNECT", dest, status, 1000+i%5000, blocked, reason); err != nil {
			t.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
