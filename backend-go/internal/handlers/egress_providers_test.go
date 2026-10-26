package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

type fakeProviderFeedServer struct {
	mu      sync.Mutex
	sha     string
	v4      map[string]string
	v6      map[string]string
	v4Code  map[string]int
	v6Code  map[string]int
	urlBody map[string]string
	reqs    []string
}

func newFakeProviderFeedServer(t *testing.T, sha string) (*fakeProviderFeedServer, *httptest.Server) {
	t.Helper()
	f := &fakeProviderFeedServer{
		sha:     sha,
		v4:      map[string]string{},
		v6:      map[string]string{},
		v4Code:  map[string]int{},
		v6Code:  map[string]int{},
		urlBody: map[string]string{},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.Method+" "+r.URL.Path)
		sha := f.sha
		f.mu.Unlock()

		if r.URL.Path == "/commits/main" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"sha":%q}`, sha)
			return
		}
		f.mu.Lock()
		if body, ok := f.urlBody[r.URL.Path]; ok {
			f.mu.Unlock()
			_, _ = w.Write([]byte(body))
			return
		}
		f.mu.Unlock()

		prefix := "/" + sha + "/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		dir, file := parts[0], parts[1]
		f.mu.Lock()
		defer f.mu.Unlock()
		switch file {
		case "ipv4_merged.txt":
			if code, ok := f.v4Code[dir]; ok && code != http.StatusOK {
				w.WriteHeader(code)
				return
			}
			body, ok := f.v4[dir]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(body))
		case "ipv6_merged.txt":
			if code, ok := f.v6Code[dir]; ok && code != http.StatusOK {
				w.WriteHeader(code)
				return
			}
			body, ok := f.v6[dir]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(body))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	origCommits := workers.EgressCommitsURL
	origRaw := workers.EgressRawBaseURL
	origClient := workers.EgressHTTPClient
	origCheck := workers.EgressCheckURL

	workers.EgressCommitsURL = srv.URL + "/commits/main"
	workers.EgressRawBaseURL = srv.URL
	workers.EgressHTTPClient = func() *http.Client { return srv.Client() }
	workers.EgressCheckURL = func(rawURL string) (bool, error) {
		if strings.HasPrefix(rawURL, srv.URL) {
			return false, nil
		}
		return origCheck(rawURL)
	}
	t.Cleanup(func() {
		workers.EgressCommitsURL = origCommits
		workers.EgressRawBaseURL = origRaw
		workers.EgressHTTPClient = origClient
		workers.EgressCheckURL = origCheck
	})
	return f, srv
}

func (f *fakeProviderFeedServer) setCatalog(dir, v4, v6 string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.v4[dir] = v4
	f.v6[dir] = v6
	delete(f.v4Code, dir)
	delete(f.v6Code, dir)
}

func (f *fakeProviderFeedServer) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.reqs))
	copy(out, f.reqs)
	return out
}

func (f *fakeProviderFeedServer) clearRequests() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = nil
}

func egressRouter(t *testing.T, db *sql.DB, cfg *config.Config) http.Handler {
	t.Helper()
	asAdmin := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, withUserContext(req, "admin"))
		})
	}
	r := chi.NewRouter()
	NewBlacklistHandlers(db, cfg).Register(r, asAdmin)
	NewMaintenanceHandlers(db, cfg).Register(r, asAdmin)
	NewDatabaseHandlers(db).Register(r, asAdmin)
	registerEgressProvidersOnRouter(r, db, cfg, asAdmin)
	return r
}

func providerEntriesInDB(t *testing.T, db *sql.DB, name string) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT e.cidr
		FROM egress_provider_entries e
		JOIN egress_providers p ON p.id = e.provider_id
		WHERE p.name = ?
		ORDER BY e.cidr`, name)
	if err != nil {
		t.Fatalf("query entries for %s: %v", name, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func providerStateInDB(t *testing.T, db *sql.DB, name string) (lastCommit, lastError, heldJSON string) {
	t.Helper()
	_ = db.QueryRow(`SELECT COALESCE(last_commit,''), COALESCE(last_error,''), COALESCE(held_json,'') FROM egress_providers WHERE name = ?`, name).
		Scan(&lastCommit, &lastError, &heldJSON)
	return
}

// buildExactIPv4List returns a newline-joined list of non-overlapping public
// IPv4 prefixes under 11.x.y.z whose total covered IPv4 address count equals n.
func buildExactIPv4List(n int) string {
	var lines []string
	addr := uint32(11<<24 | 1<<16) // 11.1.0.0, public space
	rem := n
	for bit := 24; bit <= 32 && rem > 0; bit++ {
		block := 1 << (32 - bit)
		for rem >= block {
			b0 := byte(addr >> 24)
			b1 := byte(addr >> 16)
			b2 := byte(addr >> 8)
			b3 := byte(addr)
			lines = append(lines, fmt.Sprintf("%d.%d.%d.%d/%d", b0, b1, b2, b3, bit))
			addr += uint32(block)
			rem -= block
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestEgressProviderProtections(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	feed, _ := newFakeProviderFeedServer(t, "d03d319a255c0000000000000000000000000001")
	h := egressRouter(t, db, cfg)

	// 1. Seed a good initial list for telegram (not a shared network).
	feed.setCatalog("telegram", "1.1.1.0/24\n8.8.8.0/24\n", "2606:4700::/32\n")
	if code, out := call(t, h, "PUT", "/api/egress-providers/telegram", `{"enabled":true}`); code != http.StatusOK {
		t.Fatalf("enable telegram = %d %v", code, out)
	}
	goodEntries := []string{"1.1.1.0/24", "2606:4700::/32", "8.8.8.0/24"}
	if got := providerEntriesInDB(t, db, "telegram"); strings.Join(got, ",") != strings.Join(goodEntries, ",") {
		t.Fatalf("initial good entries = %v, want %v", got, goodEntries)
	}

	// Build a 50,001-line public list.
	var over50k strings.Builder
	for i := 0; i < 50001; i++ {
		b1 := (i >> 16) & 0xff
		b2 := (i >> 8) & 0xff
		b3 := i & 0xff
		fmt.Fprintf(&over50k, "11.%d.%d.%d/32\n", b1, b2, b3)
	}

	failCases := []struct {
		name string
		v4   string
		v6   string
	}{
		{"malformed_line", "1.1.1.0/24\nnot-a-cidr\n", "2606:4700::/32\n"},
		{"v4_wider_than_8", "2.0.0.0/7\n", "2606:4700::/32\n"},
		{"v6_wider_than_16", "1.1.1.0/24\n", "2600::/15\n"},
		{"nonpublic_private_10", "10.1.0.0/16\n", ""},
		{"nonpublic_private_172", "172.16.0.0/16\n", ""},
		{"nonpublic_private_192", "192.168.1.0/24\n", ""},
		{"nonpublic_loopback_v4", "127.0.0.0/24\n", ""},
		{"nonpublic_loopback_v6", "1.1.1.0/24\n", "::1/128\n"},
		{"nonpublic_link_local_v4", "169.254.1.0/24\n", ""},
		{"nonpublic_link_local_v6", "1.1.1.0/24\n", "fe80::/64\n"},
		{"nonpublic_multicast_v4", "224.0.0.0/24\n", ""},
		{"nonpublic_multicast_v6", "1.1.1.0/24\n", "ff02::/16\n"},
		{"nonpublic_reserved_0", "0.0.0.0/8\n", ""},
		{"nonpublic_reserved_240", "240.0.0.0/24\n", ""},
		{"nonpublic_reserved_benchmark", "198.18.0.0/24\n", ""},
		{"nonpublic_reserved_v6_unspec", "1.1.1.0/24\n", "::/128\n"},
		{"nonpublic_doc_192_0_2", "192.0.2.0/24\n", ""},
		{"nonpublic_doc_198_51_100", "198.51.100.0/24\n", ""},
		{"nonpublic_doc_203_0_113", "203.0.113.0/24\n", ""},
		{"nonpublic_doc_v6_2001_db8", "1.1.1.0/24\n", "2001:db8::/32\n"},
		{"nonpublic_cgnat", "100.64.0.0/16\n", ""},
		{"nonpublic_ula", "1.1.1.0/24\n", "fd00::/48\n"},
		{"over_50000_entries", over50k.String(), ""},
	}

	for i, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			beforeFailedAudit := len(auditRows(t, db, "egress_provider_refresh_failed"))
			feed.mu.Lock()
			feed.sha = fmt.Sprintf("badcommit%032d", i+1)
			feed.mu.Unlock()
			feed.setCatalog("telegram", tc.v4, tc.v6)

			code, out := call(t, h, "POST", "/api/egress-providers/telegram/refresh", "")
			if code == http.StatusOK {
				t.Fatalf("%s: refresh succeeded unexpectedly: %v", tc.name, out)
			}
			// Last good list must remain intact.
			if got := providerEntriesInDB(t, db, "telegram"); strings.Join(got, ",") != strings.Join(goodEntries, ",") {
				t.Fatalf("%s: previous good list was altered: got %v, want %v", tc.name, got, goodEntries)
			}
			// last_error must be populated and last_commit must still be the good commit.
			commit, lastErr, _ := providerStateInDB(t, db, "telegram")
			if lastErr == "" {
				t.Errorf("%s: last_error is empty after failed refresh", tc.name)
			}
			if commit != "d03d319a255c0000000000000000000000000001" {
				t.Errorf("%s: last_commit changed to %q on failed refresh", tc.name, commit)
			}
			// Audit row egress_provider_refresh_failed must be written with reason.
			afterFailedAudit := auditRows(t, db, "egress_provider_refresh_failed")
			if len(afterFailedAudit) != beforeFailedAudit+1 {
				t.Fatalf("%s: egress_provider_refresh_failed rows = %d, want %d", tc.name, len(afterFailedAudit), beforeFailedAudit+1)
			}
			lastRow := afterFailedAudit[len(afterFailedAudit)-1]
			if lastRow.target != "telegram" || !strings.Contains(lastRow.details, "reason") {
				t.Errorf("%s: audit row = %+v", tc.name, lastRow)
			}
		})
	}

	// 2. Growth threshold: 25.0% is applied, 25.1% is held in held_json.
	t.Run("growth_25_0_applied_and_25_1_held", func(t *testing.T) {
		feed.mu.Lock()
		feed.sha = "d03d319a255c0000000000000000000000000010"
		feed.mu.Unlock()
		feed.setCatalog("facebook", buildExactIPv4List(1000), "")
		if code, out := call(t, h, "PUT", "/api/egress-providers/facebook", `{"enabled":true}`); code != http.StatusOK {
			t.Fatalf("enable facebook (1000 addrs) = %d %v", code, out)
		}

		// 25.0% growth (1000 -> 1250 addresses): must be applied, not held.
		feed.mu.Lock()
		feed.sha = "d03d319a255c0000000000000000000000000011"
		feed.mu.Unlock()
		feed.setCatalog("facebook", buildExactIPv4List(1250), "")
		if code, out := call(t, h, "POST", "/api/egress-providers/facebook/refresh", ""); code != http.StatusOK {
			t.Fatalf("refresh 25.0%% growth = %d %v", code, out)
		}
		commit, lastErr, heldJSON := providerStateInDB(t, db, "facebook")
		if commit != "d03d319a255c0000000000000000000000000011" || lastErr != "" || heldJSON != "" {
			t.Fatalf("after 25.0%% growth: commit=%q err=%q held=%q", commit, lastErr, heldJSON)
		}

		// Reset facebook to 1000 addresses to test 25.1% growth (1000 -> 1251 addresses).
		feed.mu.Lock()
		feed.sha = "d03d319a255c0000000000000000000000000012"
		feed.mu.Unlock()
		feed.setCatalog("facebook", buildExactIPv4List(1000), "")
		if code, out := call(t, h, "POST", "/api/egress-providers/facebook/refresh", ""); code != http.StatusOK {
			t.Fatalf("reset facebook to 1000 = %d %v", code, out)
		}
		entriesAt1000 := providerEntriesInDB(t, db, "facebook")

		// 25.1% growth (1000 -> 1251 addresses): must be held in held_json, previous list stays intact.
		beforeHeldAudit := len(auditRows(t, db, "egress_provider_held"))
		feed.mu.Lock()
		feed.sha = "d03d319a255c0000000000000000000000000013"
		feed.mu.Unlock()
		feed.setCatalog("facebook", buildExactIPv4List(1251), "")
		code, out := call(t, h, "POST", "/api/egress-providers/facebook/refresh", "")
		if code != http.StatusOK {
			t.Fatalf("refresh 25.1%% growth = %d %v", code, out)
		}
		if got := providerEntriesInDB(t, db, "facebook"); strings.Join(got, ",") != strings.Join(entriesAt1000, ",") {
			t.Fatalf("25.1%% growth modified active entries: got %v, want %v", got, entriesAt1000)
		}
		commit, lastErr, heldJSON = providerStateInDB(t, db, "facebook")
		if commit != "d03d319a255c0000000000000000000000000012" || lastErr != "" || heldJSON == "" {
			t.Fatalf("after 25.1%% growth: commit=%q err=%q held=%q (expected held_json)", commit, lastErr, heldJSON)
		}
		heldAudits := auditRows(t, db, "egress_provider_held")
		if len(heldAudits) != beforeHeldAudit+1 {
			t.Fatalf("egress_provider_held audit rows = %d, want %d", len(heldAudits), beforeHeldAudit+1)
		}
		if !strings.Contains(heldAudits[len(heldAudits)-1].details, "25.1") {
			t.Errorf("egress_provider_held details = %s, want growth_pct 25.1", heldAudits[len(heldAudits)-1].details)
		}

		// Apply the held update via POST /api/egress-providers/facebook/apply-held.
		if code, out := call(t, h, "POST", "/api/egress-providers/facebook/apply-held", ""); code != http.StatusOK {
			t.Fatalf("apply-held = %d %v", code, out)
		}
		commit, _, heldJSON = providerStateInDB(t, db, "facebook")
		if commit != "d03d319a255c0000000000000000000000000013" || heldJSON != "" {
			t.Fatalf("after apply-held: commit=%q held=%q", commit, heldJSON)
		}
		appliedRow := oneAuditRow(t, db, "egress_provider_held_applied")
		if appliedRow.user != "admin" || appliedRow.target != "facebook" || !strings.Contains(appliedRow.details, "1251") {
			t.Errorf("egress_provider_held_applied = %+v", appliedRow)
		}
	})
}

func TestEgressProviderCommitPinnedFetch(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	const pinnedSHA = "d03d319a255c99887766554433221100ffeeddcc"
	feed, _ := newFakeProviderFeedServer(t, pinnedSHA)
	h := egressRouter(t, db, cfg)

	feed.setCatalog("twitter", "104.244.40.0/21\n", "2620:101:9000::/40\n")
	feed.clearRequests()

	if code, out := call(t, h, "PUT", "/api/egress-providers/twitter", `{"enabled":true}`); code != http.StatusOK {
		t.Fatalf("enable twitter = %d %v", code, out)
	}

	reqs := feed.requests()
	wantReqs := []string{
		"GET /commits/main",
		"GET /" + pinnedSHA + "/twitter/ipv4_merged.txt",
		"GET /" + pinnedSHA + "/twitter/ipv6_merged.txt",
	}
	if strings.Join(reqs, ",") != strings.Join(wantReqs, ",") {
		t.Fatalf("fetch requests = %v, want %v", reqs, wantReqs)
	}

	// Verify audit row contains the pinned SHA and before/after counts.
	refreshedRows := auditRows(t, db, "egress_provider_refreshed")
	if len(refreshedRows) == 0 {
		t.Fatalf("expected egress_provider_refreshed audit row")
	}
	lastRefreshAudit := refreshedRows[len(refreshedRows)-1]
	if !strings.Contains(lastRefreshAudit.details, pinnedSHA) {
		t.Errorf("audit row details %s missing commit %s", lastRefreshAudit.details, pinnedSHA)
	}

	// 404 on ipv6_merged.txt (like oracle) counts as an empty IPv6 list, not a failure.
	feed.mu.Lock()
	feed.v4["oracle"] = "129.146.0.0/16\n"
	feed.v6Code["oracle"] = http.StatusNotFound
	feed.mu.Unlock()
	if code, out := call(t, h, "PUT", "/api/egress-providers/oracle", `{"enabled":true,"confirm_shared":true}`); code != http.StatusOK {
		t.Fatalf("enable oracle (404 on v6) = %d %v", code, out)
	}
	if got := providerEntriesInDB(t, db, "oracle"); strings.Join(got, ",") != "129.146.0.0/16" {
		t.Fatalf("oracle entries = %v, want [129.146.0.0/16]", got)
	}

	// 404 on ipv4_merged.txt is a failure and keeps previous entries intact.
	feed.mu.Lock()
	feed.v4Code["oracle"] = http.StatusNotFound
	feed.mu.Unlock()
	if code, out := call(t, h, "POST", "/api/egress-providers/oracle/refresh", ""); code == http.StatusOK {
		t.Fatalf("expected 404 on ipv4_merged.txt to fail, got 200: %v", out)
	}
	if got := providerEntriesInDB(t, db, "oracle"); strings.Join(got, ",") != "129.146.0.0/16" {
		t.Fatalf("oracle entries after v4 404 = %v, want [129.146.0.0/16]", got)
	}
}

func TestEgressProviderAPIAndExport(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	feed, srv := newFakeProviderFeedServer(t, "d03d319a255caabbccddeeff0011223344556677")
	feed.setCatalog("cloudflare", "1.1.1.0/24\n104.16.0.0/13\n", "2606:4700::/32\n")
	feed.setCatalog("telegram", "149.154.160.0/20\n", "")
	feed.setCatalog("all", "1.1.1.0/24\n149.154.160.0/20\n", "")
	feed.mu.Lock()
	feed.urlBody["/custom-egress.txt"] = "# custom comment\n\n9.9.9.0/24\n2620:fe::/48\n"
	feed.mu.Unlock()

	h := egressRouter(t, db, cfg)

	// 1. Unauthenticated requests must return 401.
	denyRouter := buildFullRouterWithAuth(t, func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	})
	for _, reqSpec := range [][2]string{
		{"GET", "/api/egress-providers"},
		{"PUT", "/api/egress-providers/cloudflare"},
		{"POST", "/api/egress-providers/url"},
		{"DELETE", "/api/egress-providers/url/1"},
		{"POST", "/api/egress-providers/cloudflare/refresh"},
		{"POST", "/api/egress-providers/cloudflare/apply-held"},
	} {
		w := httptest.NewRecorder()
		denyRouter.ServeHTTP(w, httptest.NewRequest(reqSpec[0], reqSpec[1], nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without token = %d, want 401", reqSpec[0], reqSpec[1], w.Code)
		}
	}

	// 2. Shared-network providers and 'all' require confirm_shared: true.
	if code, out := call(t, h, "PUT", "/api/egress-providers/cloudflare", `{"enabled":true}`); code != http.StatusBadRequest {
		t.Fatalf("cloudflare without confirm_shared = %d %v, want 400", code, out)
	}
	if code, out := call(t, h, "PUT", "/api/egress-providers/all", `{"enabled":true}`); code != http.StatusBadRequest {
		t.Fatalf("all without confirm_shared = %d %v, want 400", code, out)
	}
	if code, out := call(t, h, "PUT", "/api/egress-providers/cloudflare", `{"enabled":true,"confirm_shared":true}`); code != http.StatusOK {
		t.Fatalf("cloudflare with confirm_shared = %d %v, want 200", code, out)
	}
	oneAuditRow(t, db, "egress_provider_enabled")

	// 3. Unknown provider name outside catalog (e.g. bing) -> 400.
	if code, out := call(t, h, "PUT", "/api/egress-providers/bing", `{"enabled":true,"confirm_shared":true}`); code != http.StatusBadRequest {
		t.Fatalf("unknown provider bing = %d %v, want 400", code, out)
	}

	// 4. Custom URL provider add and delete, plus manual dst_allowlist union and clear-all isolation.
	if code, out := call(t, h, "POST", "/api/egress-allowlist", `{"entry":"1.1.1.0/24","description":"dup with cloudflare"}`); code != http.StatusOK {
		t.Fatalf("add manual egress cidr = %d %v", code, out)
	}
	if code, out := call(t, h, "POST", "/api/egress-allowlist", `{"entry":"8.8.4.0/24","description":"manual only"}`); code != http.StatusOK {
		t.Fatalf("add second manual egress cidr = %d %v", code, out)
	}

	code, urlOut := call(t, h, "POST", "/api/egress-providers/url", fmt.Sprintf(`{"url":%q,"label":"quad9"}`, srv.URL+"/custom-egress.txt"))
	if code != http.StatusOK {
		t.Fatalf("POST /api/egress-providers/url = %d %v", code, urlOut)
	}

	// Verify exported dst_allow_ip.txt has the sorted deduplicated union of manual + enabled providers.
	raw, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "dst_allow_ip.txt"))
	if err != nil {
		t.Fatalf("read dst_allow_ip.txt: %v", err)
	}
	wantExport := "1.1.1.0/24\n104.16.0.0/13\n2606:4700::/32\n2620:fe::/48\n8.8.4.0/24\n9.9.9.0/24"
	if got := strings.TrimSpace(string(raw)); got != wantExport {
		t.Fatalf("dst_allow_ip.txt =\n%s\nwant:\n%s", got, wantExport)
	}

	// Clear-all on manual egress allowlist must not touch provider entries.
	if code, out := call(t, h, "DELETE", "/api/egress-allowlist/clear-all", ""); code != http.StatusOK {
		t.Fatalf("clear-all manual egress = %d %v", code, out)
	}
	if err := database.ExportBlacklistsToFiles(db, cfg.ConfigDir); err != nil {
		t.Fatal(err)
	}
	rawAfterClear, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "dst_allow_ip.txt"))
	if err != nil {
		t.Fatal(err)
	}
	wantAfterClear := "1.1.1.0/24\n104.16.0.0/13\n2606:4700::/32\n2620:fe::/48\n9.9.9.0/24"
	if got := strings.TrimSpace(string(rawAfterClear)); got != wantAfterClear {
		t.Fatalf("after manual clear-all, dst_allow_ip.txt =\n%s\nwant:\n%s", got, wantAfterClear)
	}

	// Disabling cloudflare removes its entries from dst_allow_ip.txt but keeps them in egress_provider_entries.
	if code, out := call(t, h, "PUT", "/api/egress-providers/cloudflare", `{"enabled":false}`); code != http.StatusOK {
		t.Fatalf("disable cloudflare = %d %v", code, out)
	}
	oneAuditRow(t, db, "egress_provider_disabled")
	if len(providerEntriesInDB(t, db, "cloudflare")) != 3 {
		t.Fatalf("disabled cloudflare lost its cached entries in DB")
	}
	rawAfterDisable, _ := os.ReadFile(filepath.Join(cfg.ConfigDir, "dst_allow_ip.txt"))
	if got := strings.TrimSpace(string(rawAfterDisable)); got != "2620:fe::/48\n9.9.9.0/24" {
		t.Fatalf("after disabling cloudflare, dst_allow_ip.txt = %q, want quad9 only", got)
	}

	// Deleting the URL provider removes both the provider and its entries.
	var urlID int64
	if err := db.QueryRow("SELECT id FROM egress_providers WHERE kind = 'url' AND name = 'quad9'").Scan(&urlID); err != nil {
		t.Fatalf("find quad9 id: %v", err)
	}
	if code, out := call(t, h, "DELETE", fmt.Sprintf("/api/egress-providers/url/%d", urlID), ""); code != http.StatusOK {
		t.Fatalf("delete quad9 = %d %v", code, out)
	}
	if got := providerEntriesInDB(t, db, "quad9"); len(got) != 0 {
		t.Fatalf("deleted URL provider still has entries: %v", got)
	}
}

func TestEgressProviderBackupRestoreAndReset(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	feed, srv := newFakeProviderFeedServer(t, "d03d319a255c1234567890abcdef1234567890ab")
	feed.setCatalog("telegram", "149.154.160.0/20\n", "")
	feed.mu.Lock()
	feed.urlBody["/custom.txt"] = "9.9.9.0/24\n"
	feed.mu.Unlock()

	h := egressRouter(t, db, cfg)
	if code, out := call(t, h, "PUT", "/api/egress-providers/telegram", `{"enabled":true}`); code != http.StatusOK {
		t.Fatalf("enable telegram = %d %v", code, out)
	}
	if code, out := call(t, h, "POST", "/api/egress-providers/url", fmt.Sprintf(`{"url":%q,"label":"custom"}`, srv.URL+"/custom.txt")); code != http.StatusOK {
		t.Fatalf("add url provider = %d %v", code, out)
	}

	// Backup captures enabled providers and URL providers, not entries.
	code, backupResp := call(t, h, "GET", "/api/maintenance/backup-config", "")
	if code != http.StatusOK {
		t.Fatalf("backup = %d %v", code, backupResp)
	}
	backupData, _ := backupResp["data"].(map[string]any)
	provList, ok := backupData["egress_providers"].([]any)
	if !ok || len(provList) != 2 {
		t.Fatalf("backup egress_providers = %v, want 2 items", backupData["egress_providers"])
	}

	// Database reset clears egress_provider_entries before egress_providers without foreign key errors.
	if code, out := call(t, h, "POST", "/api/database/reset", `{"confirm":"RESET"}`); code != http.StatusOK {
		t.Fatalf("reset = %d %v", code, out)
	}
	if got := providerEntriesInDB(t, db, "telegram"); len(got) != 0 {
		t.Fatalf("entries after reset = %v, want empty", got)
	}

	// Restore re-creates the providers and downloads their entries again.
	if code, out := call(t, h, "POST", "/api/maintenance/restore-config", mustJSON(t, backupData)); code != http.StatusOK {
		t.Fatalf("restore = %d %v", code, out)
	}
	if got := providerEntriesInDB(t, db, "telegram"); strings.Join(got, ",") != "149.154.160.0/20" {
		t.Fatalf("telegram entries after restore = %v, want [149.154.160.0/20]", got)
	}
	if got := providerEntriesInDB(t, db, "custom"); strings.Join(got, ",") != "9.9.9.0/24" {
		t.Fatalf("custom entries after restore = %v, want [9.9.9.0/24]", got)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	return fmt.Sprintf(`{"backup_version":2,"settings":{"egress_provider_refresh_hours":"24"},"egress_providers":[{"kind":"catalog","name":"telegram","url":"","enabled":true},{"kind":"url","name":"custom","url":%q,"enabled":true}]}`, v.(map[string]any)["egress_providers"].([]any)[1].(map[string]any)["url"])
}
