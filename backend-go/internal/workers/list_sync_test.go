package workers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// serveFeeds answers fetchRefreshFeed from feeds for the rest of the test; a
// URL not in it fails with HTTP 410.
func serveFeeds(t *testing.T, feeds map[string]string) {
	t.Helper()
	orig := fetchRefreshFeed
	fetchRefreshFeed = func(u string) (string, error) {
		if body, ok := feeds[u]; ok {
			return body, nil
		}
		return "", errors.New("HTTP 410")
	}
	t.Cleanup(func() { fetchRefreshFeed = orig })
}

// hosts is a hosts-file feed listing names.
func hosts(names ...string) string {
	var b strings.Builder
	for _, n := range names {
		b.WriteString("0.0.0.0 " + n + "\n")
	}
	return b.String()
}

// listed is the domain list as "name<-source" pairs, sorted; "manual" names
// the manual source, a URL a url source.
func listed(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT d.domain, COALESCE(s.kind, '') || ':' || COALESCE(s.source, '')
		FROM domain_blacklist d LEFT JOIN list_sources s ON s.id = d.source_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d, src string
		if err := rows.Scan(&d, &src); err != nil {
			t.Fatal(err)
		}
		out = append(out, d+"<-"+strings.TrimSuffix(src, ":"))
	}
	sort.Strings(out)
	return out
}

const (
	feedA = "https://a.test/hosts"
	feedB = "https://b.test/hosts"
)

func syncDomains(db *sql.DB, urls ...string) refreshCount {
	return refreshList(db, "domain_blacklist", urls)
}

func expectListed(t *testing.T, db *sql.DB, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := listed(t, db); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("list = %v\nwant   %v", got, want)
	}
}

// A feed that drops an entry takes it out of the list; one it adds goes in.
func TestRefreshRemovesWhatAFeedDropped(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test", "c.test", "d.test")})
	if c := syncDomains(db, feedA); c.Added != 4 || c.Removed != 0 {
		t.Fatalf("first run = %+v; want 4 added", c)
	}
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test", "c.test", "e.test")})
	c := syncDomains(db, feedA)
	if want := (refreshCount{Added: 1, Removed: 1, Fetched: 1}); c != want {
		t.Errorf("second run = %+v; want %+v", c, want)
	}
	expectListed(t, db, "a.test<-url:"+feedA, "b.test<-url:"+feedA, "c.test<-url:"+feedA, "e.test<-url:"+feedA)
}

// An entry its first feed dropped while another feed of the same run still
// lists it stays, under that feed: removing it would unblock what a list the
// admin chose still names.
func TestAnEntryAnotherFeedStillListsMovesToIt(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test", "x.test"), feedB: hosts("y.test")})
	syncDomains(db, feedA, feedB)
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test"), feedB: hosts("x.test", "y.test")})
	c := syncDomains(db, feedA, feedB)
	if c.Moved != 1 || c.Removed != 0 || c.Added != 0 {
		t.Errorf("run = %+v; want x.test moved to B, nothing removed", c)
	}
	expectListed(t, db, "a.test<-url:"+feedA, "b.test<-url:"+feedA, "x.test<-url:"+feedB, "y.test<-url:"+feedB)
}

// Entries added by hand are never compared with a feed: one a feed also
// listed, then dropped, stays, and so does one no feed lists.
func TestManualEntriesAreNeverRemoved(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	manual, err := database.KeyedSource(db, "domain_blacklist", database.SourceManual, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"m.test", "shared.test"} {
		if _, err := db.Exec("INSERT INTO domain_blacklist(domain, source_id) VALUES(?, ?)", d, manual); err != nil {
			t.Fatal(err)
		}
	}
	serveFeeds(t, map[string]string{feedA: hosts("shared.test", "a.test", "b.test")})
	syncDomains(db, feedA)
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test")})
	if c := syncDomains(db, feedA); c.Removed != 0 {
		t.Errorf("run = %+v; want nothing removed", c)
	}
	expectListed(t, db, "m.test<-manual", "shared.test<-manual", "a.test<-url:"+feedA, "b.test<-url:"+feedA)
}

// A feed that answers with fewer than half the entries it added, or with
// none, is held: a truncated or replaced file is likelier than a feed that
// dropped half its threats. Its entries stay, and its source says so.
func TestAFeedThatShrankByMoreThanHalfIsHeld(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"shrank to 4 of 10", hosts("n0.test", "n1.test", "n2.test", "n3.test")},
		{"empty", "# nothing\n"},
		{"an error page", "<html><body>Rate limited</body></html>\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			var ten []string
			for i := 0; i < 10; i++ {
				ten = append(ten, fmt.Sprintf("n%d.test", i))
			}
			serveFeeds(t, map[string]string{feedA: hosts(ten...)})
			syncDomains(db, feedA)
			serveFeeds(t, map[string]string{feedA: tc.body})
			c := syncDomains(db, feedA)
			if c.Removed != 0 || c.Held != 1 {
				t.Errorf("run = %+v; want held, nothing removed", c)
			}
			if got := len(listed(t, db)); got != 10 {
				t.Errorf("list holds %d, want the 10 kept", got)
			}
			var status, detail string
			_ = db.QueryRow("SELECT refresh_status, refresh_detail FROM list_sources WHERE source = ?", feedA).Scan(&status, &detail)
			if status != "held" || !strings.Contains(detail, "of the 10 it added") {
				t.Errorf("source note = %q %q; want held, naming the 10", status, detail)
			}
		})
	}
}

// Exactly half is not held: the rule is "fewer than half".
func TestAFeedThatKeptHalfIsSynced(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test", "c.test", "d.test")})
	syncDomains(db, feedA)
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test")})
	if c := syncDomains(db, feedA); c.Held != 0 || c.Removed != 2 {
		t.Errorf("run = %+v; want 2 removed, none held", c)
	}
}

// While a feed of the list cannot be downloaded, nothing of that list is
// removed: the entry another feed dropped may be one the missing feed lists
// under another source. Entries still move, and the next full run removes.
func TestRemovalWaitsWhileAFeedOfTheListFails(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test", "d.test"), feedB: hosts("y.test")})
	syncDomains(db, feedA, feedB)

	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test")}) // B answers 410
	c := syncDomains(db, feedA, feedB)
	if c.Removed != 0 || !c.RemovalDeferred || c.Failed != 1 {
		t.Errorf("run with B down = %+v; want nothing removed, removal deferred", c)
	}
	expectListed(t, db, "a.test<-url:"+feedA, "b.test<-url:"+feedA, "d.test<-url:"+feedA, "y.test<-url:"+feedB)
	var status, detail string
	_ = db.QueryRow("SELECT refresh_status, refresh_detail FROM list_sources WHERE source = ?", feedB).Scan(&status, &detail)
	if status != "failed" || detail != "not downloaded: the server answered HTTP 410" {
		t.Errorf("B's note = %q %q", status, detail)
	}

	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test"), feedB: hosts("y.test")})
	if c := syncDomains(db, feedA, feedB); c.Removed != 1 || c.RemovalDeferred {
		t.Errorf("run with both up = %+v; want d.test removed", c)
	}
	expectListed(t, db, "a.test<-url:"+feedA, "b.test<-url:"+feedA, "y.test<-url:"+feedB)
}

// The refresh downloads every URL a list was imported from that still has
// entries, not only the built-in feeds and the setting, each once.
func TestTheRefreshCoversEveryImportedURL(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	withEntry := func(list, url, entry string) {
		t.Helper()
		id, err := database.KeyedSource(db, list, database.SourceURL, url, "")
		if err != nil {
			t.Fatal(err)
		}
		col := map[string]string{"domain_blacklist": "domain", "ip_blacklist": "ip"}[list]
		if _, err := db.Exec("INSERT INTO "+list+"("+col+", source_id) VALUES(?, ?)", entry, id); err != nil {
			t.Fatal(err)
		}
	}
	const imported = "https://imported.test/list.txt"
	withEntry("domain_blacklist", imported, "imported.example")
	// The built-in StevenBlack feed imported by hand too: listed once.
	withEntry("domain_blacklist", defaultDomainLists[0], "steven.example")
	got := feedURLs(db, "domain_blacklist", defaultDomainLists, "https://setting.test/x\n\n"+imported)
	want := append(append([]string{}, defaultDomainLists...), "https://setting.test/x", imported)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("feeds = %v\nwant    %v", got, want)
	}
	// An imported IP list is not a domain feed.
	withEntry("ip_blacklist", "https://ips.test/l", "203.0.113.9")
	if ip := feedURLs(db, "ip_blacklist", nil, ""); strings.Join(ip, " ") != "https://ips.test/l" {
		t.Errorf("ip feeds = %v", ip)
	}
}

// A url source left with no entry (the list was cleared) is not refreshed:
// the sources table does not show it, so it could neither be seen nor
// removed while it refilled the list.
func TestAClearedListIsNotRefilledByAHiddenSource(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	const imported = "https://imported.test/list.txt"
	serveFeeds(t, map[string]string{imported: hosts("a.test", "b.test")})
	syncDomains(db, imported)
	if _, err := db.Exec("DELETE FROM domain_blacklist"); err != nil { // Remove every entry on this list
		t.Fatal(err)
	}
	if got := feedURLs(db, "domain_blacklist", nil, ""); len(got) != 0 {
		t.Errorf("feeds after clearing = %v; want none", got)
	}
}

// A source whose every entry moved to another feed is removed with them, so
// no source without entries stays to be refreshed.
func TestASourceLeftEmptyIsRemoved(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	serveFeeds(t, map[string]string{feedA: hosts("x.test"), feedB: hosts("y.test")})
	syncDomains(db, feedA, feedB)
	// A now lists z.test instead of x.test, which B lists: x.test moves to B.
	serveFeeds(t, map[string]string{feedA: hosts("z.test"), feedB: hosts("x.test", "y.test")})
	syncDomains(db, feedA, feedB)
	expectListed(t, db, "x.test<-url:"+feedB, "y.test<-url:"+feedB, "z.test<-url:"+feedA)
	// z.test removed by hand; A lists only x.test, which B holds: A has no
	// entry left after the run, and its source goes.
	if _, err := db.Exec("DELETE FROM domain_blacklist WHERE domain = 'z.test'"); err != nil {
		t.Fatal(err)
	}
	serveFeeds(t, map[string]string{feedA: hosts("x.test"), feedB: hosts("x.test", "y.test")})
	syncDomains(db, feedA, feedB)
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM list_sources WHERE source = ?", feedA).Scan(&n)
	if n != 0 {
		t.Errorf("A's source with no entry left is still there")
	}
}

// A feed line is read as the import reads it (listentry): a URL names its
// host. An unchanged feed with a URL line must not lose that host.
func TestAFeedIsReadAsTheImportReadsIt(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	// What an import of the feed added: tracker.test from the URL line.
	id, err := database.KeyedSource(db, "domain_blacklist", database.SourceURL, feedA, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"tracker.test", "bare.test"} {
		if _, err := db.Exec("INSERT INTO domain_blacklist(domain, source_id) VALUES(?, ?)", d, id); err != nil {
			t.Fatal(err)
		}
	}
	serveFeeds(t, map[string]string{feedA: "https://tracker.test/path?x=1\nbare.test\n; a comment\n"})
	if c := syncDomains(db, feedA); c.Removed != 0 || c.Added != 0 {
		t.Errorf("run = %+v; want nothing removed or added", c)
	}
	expectListed(t, db, "bare.test<-url:"+feedA, "tracker.test<-url:"+feedA)
}

// Removals come before additions, so the room a removal frees under the
// domain limit takes an addition of the same run.
func TestARemovalMakesRoomForAnAdditionInTheSameRun(t *testing.T) {
	t.Setenv("SPM_DNS_BLOCKLIST_MAX_DOMAINS", "2")
	db, cleanup := setupTestDB(t)
	defer cleanup()
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test")})
	syncDomains(db, feedA)
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "c.test")})
	c := syncDomains(db, feedA)
	if c.Added != 1 || c.Removed != 1 || c.NotAdded != 0 {
		t.Errorf("run = %+v; want b.test removed and c.test added", c)
	}
	expectListed(t, db, "a.test<-url:"+feedA, "c.test<-url:"+feedA)
}

// Each window reads one source's rows on the (source_id, id) index: on the id
// range alone, a source whose few rows sit after a million others scanned the
// million while it held the write lock.
func TestTheWindowsReadOnlyTheirSourceRows(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := resetRefreshFeed(ctx, conn); err != nil {
		t.Fatal(err)
	}
	for table, q := range syncLists {
		for name, stmt := range map[string]string{"idBound": q.idBound, "moveStale": q.moveStale, "deleteStale": q.deleteStale} {
			rows, err := conn.QueryContext(ctx, "EXPLAIN QUERY PLAN "+stmt, 1, 1, 1, 1, 1, 1)
			if err != nil {
				rows, err = conn.QueryContext(ctx, "EXPLAIN QUERY PLAN "+stmt, 1, 1, 1, 1)
			}
			if err != nil {
				rows, err = conn.QueryContext(ctx, "EXPLAIN QUERY PLAN "+stmt, 1, 1, 1)
			}
			if err != nil {
				t.Fatalf("%s %s: %v", table, name, err)
			}
			var plan []string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				plan = append(plan, detail)
			}
			rows.Close()
			joined := strings.Join(plan, " | ")
			want := "idx_" + table + "_source_id (source_id=? AND id>?"
			if !strings.Contains(joined, want) || strings.Contains(joined, "TEMP B-TREE FOR ORDER BY") {
				t.Errorf("%s %s plan = %s; want a range of %s", table, name, joined, want)
			}
		}
	}
}

// A feed that answered and was synced says when, and how many it listed.
func TestEachSourceSaysWhenItWasRefreshed(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test")})
	syncDomains(db, feedA)
	sources, err := database.ListSources(db, "domain_blacklist")
	if err != nil || len(sources) != 1 {
		t.Fatalf("sources = %+v, %v", sources, err)
	}
	s := sources[0]
	if s.RefreshStatus != "ok" || s.RefreshDetail != "listed 2 entries" || s.RefreshedAt == "" {
		t.Errorf("source = %+v; want ok, listed 2 entries, a time", s)
	}
}

// A feed that is not read is not created as a source: a built-in feed never
// imported and down has no row to note, and gets none.
func TestAFailedFeedCreatesNoSource(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	serveFeeds(t, map[string]string{})
	syncDomains(db, feedA)
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM list_sources").Scan(&n)
	if n != 0 {
		t.Errorf("%d sources after a failed feed, want 0", n)
	}
}

func TestThousands(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 50772: "50,772", 1234567: "1,234,567", -1200: "-1,200"} {
		if got := thousands(n); got != want {
			t.Errorf("thousands(%d) = %q, want %q", n, got, want)
		}
	}
}
