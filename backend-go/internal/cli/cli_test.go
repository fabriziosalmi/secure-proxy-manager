package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// isolate gives the test a config file of its own and no SPM_* variables.
func isolate(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spm", "config.json")
	t.Setenv("SPM_CONFIG", path)
	t.Setenv("SPM_URL", "")
	t.Setenv("SPM_TOKEN", "")
	return path
}

// The config file holds a token: spm writes it 0600 in a 0700 directory, and
// refuses to read one that group or others can read.
func TestTheConfigFileIsPrivate(t *testing.T) {
	path := isolate(t)
	if err := saveConfig(path, Config{URL: "https://spm.test:8443", Token: "spm_x_y"}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	di, _ := os.Stat(filepath.Dir(path))
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("file %o, directory %o; want 600 and 700", fi.Mode().Perm(), di.Mode().Perm())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, "", "status")
	if code != exitUsage || !strings.Contains(stderr, "chmod 600") {
		t.Fatalf("a 0644 config: exit %d, %q; want 2 and the chmod to run", code, stderr)
	}
}

// A setting comes from the flag, then the environment, then the file.
func TestSettingsComeFromTheFlagThenTheEnvironmentThenTheFile(t *testing.T) {
	isolate(t)
	file := Config{URL: "https://file:8443", Token: "file-token", Fingerprint: "ab"}
	if c := resolve(file, "", ""); c.URL != "https://file:8443" || c.Token != "file-token" {
		t.Errorf("file only: %+v", c)
	}
	t.Setenv("SPM_URL", "https://env:8443")
	t.Setenv("SPM_TOKEN", "env-token")
	if c := resolve(file, "", ""); c.URL != "https://env:8443" || c.Token != "env-token" || c.Fingerprint != "ab" {
		t.Errorf("environment over file: %+v", c)
	}
	if c := resolve(file, "https://flag:8443", "flag-token"); c.URL != "https://flag:8443" || c.Token != "flag-token" {
		t.Errorf("flag over environment: %+v", c)
	}
}

// A path finds its operation in the embedded document; a literal segment
// beats a parameter, and a query does not count.
func TestAPathFindsItsOperation(t *testing.T) {
	for _, c := range []struct{ method, path, want string }{
		{"DELETE", "/api/ip-blacklist/42", "/api/ip-blacklist/{id}"},
		{"DELETE", "/api/ip-blacklist/clear-all", "/api/ip-blacklist/clear-all"},
		{"GET", "/api/logs?limit=5", "/api/logs"},
		{"POST", "/api/logs/clear-old?days=30", "/api/logs/clear-old"},
	} {
		op, ok := findOperation(c.method, c.path)
		if !ok || op.Path != c.want {
			t.Errorf("%s %s = %q (%v), want %q", c.method, c.path, op.Path, ok, c.want)
		}
	}
	if _, ok := findOperation("GET", "/api/nope"); ok {
		t.Error("GET /api/nope found an operation")
	}
	if _, ok := findOperation("PATCH", "/api/ip-blacklist"); ok {
		t.Error("PATCH /api/ip-blacklist found an operation")
	}
}

// Nothing is sent for a usage error, a body an operation does not read, or a
// dry run; the dry run prints the request instead.
func TestNothingIsSentWithoutAValidRequest(t *testing.T) {
	isolate(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"api", "GET", "/api/nope", "--url", srv.URL}, exitUsage},
		{[]string{"api", "DELETE", "/api/ip-blacklist/clear-all", "-d", `{"x":1}`, "--url", srv.URL}, exitUsage},
		{[]string{"api", "POST", "/api/ip-blacklist", "-d", `not json`, "--url", srv.URL}, exitUsage},
		{[]string{"api", "GET"}, exitUsage},
		{[]string{"nope"}, exitUsage},
	} {
		if code, _, stderr := run(t, "", c.args...); code != c.want {
			t.Errorf("%v: exit %d (%s), want %d", c.args, code, stderr, c.want)
		}
	}
	code, out, _ := run(t, "", "api", "POST", "/api/ip-blacklist", "-d", `{"ip":"203.0.113.9"}`, "--dry-run", "--url", srv.URL)
	if code != exitOK || !strings.Contains(out, "POST "+srv.URL+"/api/ip-blacklist") || !strings.Contains(out, `"203.0.113.9"`) {
		t.Errorf("dry run: exit %d, %q", code, out)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("%d requests reached the server", n)
	}
}

// The exit status says what happened: 2xx 0, 4xx 1, 5xx 3.
func TestTheExitStatusFollowsTheAnswer(t *testing.T) {
	isolate(t)
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-API-Version", "1")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":"x"}`))
	}))
	defer srv.Close()
	for s, want := range map[int]int{200: exitOK, 404: exitRefused, 409: exitRefused, 500: exitFailed, 503: exitFailed} {
		status = s
		if code, _, _ := run(t, "", "api", "GET", "/api/status", "--url", srv.URL); code != want {
			t.Errorf("answer %d: exit %d, want %d", s, code, want)
		}
	}
	srv.Close()
	if code, _, _ := run(t, "", "api", "GET", "/api/status", "--url", srv.URL); code != exitFailed {
		t.Errorf("server down: exit %d, want %d", code, exitFailed)
	}
}

// A redirect is not followed: a POST sent to the web service's plain HTTP
// port, which answers 301 to its https address, would come back from there as
// a GET of the list, a 200, and "Added". spm stops at the redirect, names its
// target, exits 3, and sends nothing to the address it was redirected to.
func TestARedirectIsAFailureThatNamesItsTarget(t *testing.T) {
	isolate(t)
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
	}))
	defer target.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.RequestURI(), http.StatusMovedPermanently)
	}))
	defer front.Close()
	for _, args := range [][]string{
		{"blocked-ips", "add", "203.0.113.7"},
		{"api", "POST", "/api/ip-blacklist", "-d", `{"ip":"203.0.113.7"}`},
		{"status"},
	} {
		code, out, stderr := run(t, "", append(args, "--url", front.URL, "--token", "spm_x_y")...)
		if code != exitFailed || !strings.Contains(stderr, "redirected to \""+target.URL+"/api/") || strings.Contains(out, "Added") {
			t.Errorf("%v: exit %d, out %q, stderr %q; want 3 and the redirect's target named", args, code, out, stderr)
		}
		t.Logf("%v: exit %d, %s", args, code, strings.TrimSpace(stderr))
	}
	if n := reached.Load(); n != 0 {
		t.Errorf("%d requests reached the address the server redirected to", n)
	}
}

// remove VALUE removes the entry written exactly as VALUE when there is one,
// even when a newer entry matches it loosely (".example.com" for
// example.com); it reads every page of the search, not only the first; and a
// loose match that fits more than one entry is refused, with nothing removed.
// The mock searches as the backend does (listHandler): a case-insensitive
// substring of the entry or its note, where "*" is a literal character, so a
// search for "*.example.com" finds no ".example.com".
func TestRemoveTakesTheEntryWrittenAsGiven(t *testing.T) {
	isolate(t)
	var entries []map[string]any // newest first, as the API lists them
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "DELETE" {
			deleted = append(deleted, r.URL.Path)
			_, _ = w.Write([]byte(`{"status":"success"}`))
			return
		}
		found := entries
		if search := strings.ToLower(r.URL.Query().Get("search")); search != "" {
			found = nil
			for _, e := range entries {
				if strings.Contains(strings.ToLower(e["entry"].(string)), search) || strings.Contains(strings.ToLower(e["description"].(string)), search) {
					found = append(found, e)
				}
			}
		}
		// Two rows a page, whatever limit asks: a server whose cap the
		// search outgrew.
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		page := []map[string]any{}
		if offset < len(found) {
			page = found[offset:min(offset+2, len(found))]
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": page, "meta": map[string]any{"total": len(found), "offset": offset}})
	}))
	defer srv.Close()
	// Every list's field carries the value, so one mock serves them all.
	entry := func(id int, v string) map[string]any {
		return map[string]any{"id": id, "entry": v, "domain": v, "ip": v, "description": ""}
	}
	for _, c := range []struct {
		name    string
		noun    string
		list    []map[string]any
		remove  string
		want    int
		deleted string
	}{
		{"exact beats a newer loose match", "allowlist", []map[string]any{entry(2, ".example.com"), entry(1, "example.com")}, "example.com", exitOK, "/api/egress-allowlist/1"},
		{"a loose match alone still counts", "allowlist", []map[string]any{entry(2, ".example.com")}, "example.com", exitOK, "/api/egress-allowlist/2"},
		{"the entry on the second page", "allowlist", []map[string]any{entry(9, "a.example.com"), entry(8, "b.example.com"), entry(7, "example.com")}, "example.com", exitOK, "/api/egress-allowlist/7"},
		{"two loose matches", "allowlist", []map[string]any{entry(4, ".example.com"), entry(3, "example.com")}, "*.example.com", exitRefused, ""},
		{"a wildcard finds the subdomain entry", "allowlist", []map[string]any{entry(5, ".example.com")}, "*.example.com", exitOK, "/api/egress-allowlist/5"},
		{"a blocked wildcard by its name", "blocked-domains", []map[string]any{entry(6, "*.ads.example.org")}, "ads.example.org", exitOK, "/api/domain-blacklist/6"},
		{"a blocked wildcard by its dotted form", "blocked-domains", []map[string]any{entry(6, "*.ads.example.org")}, ".ads.example.org", exitOK, "/api/domain-blacklist/6"},
		{"a blocked name written with an upper-case letter", "blocked-domains", []map[string]any{entry(7, "Ads.Example.org")}, "*.ads.example.org", exitOK, "/api/domain-blacklist/7"},
		{"a domain exception by its wildcard", "domain-exceptions", []map[string]any{entry(8, "cdn.example.net")}, "*.cdn.example.net", exitOK, "/api/domain-whitelist/8"},
		{"an IP", "blocked-ips", []map[string]any{entry(10, "203.0.113.70"), entry(9, "203.0.113.7")}, "203.0.113.7", exitOK, "/api/ip-blacklist/9"},
		{"a network", "ip-exceptions", []map[string]any{entry(11, "198.51.100.0/24")}, "198.51.100.0/24", exitOK, "/api/ip-whitelist/11"},
	} {
		entries, deleted = c.list, nil
		code, _, stderr := run(t, "", c.noun, "remove", c.remove, "--url", srv.URL, "--token", "spm_x_y")
		got := strings.Join(deleted, ",")
		if code != c.want || got != c.deleted || (c.want == exitRefused && !strings.Contains(stderr, "matches more than one entry")) {
			t.Errorf("%s: exit %d, deleted %q (%s); want %d and %q", c.name, code, got, strings.TrimSpace(stderr), c.want, c.deleted)
		}
		t.Logf("%s: exit %d, deleted %q %s", c.name, code, got, strings.TrimSpace(stderr))
	}
}

// spm login reuses the saved token only for the server it was saved for. For
// another server it asks for one, instead of sending the first server's token
// to the one it just started to trust; and when the server refuses a reused
// token, it says to give a new one.
func TestLoginReusesTheSavedTokenOnlyForItsServer(t *testing.T) {
	path := isolate(t)
	server := func(seen *[]string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*seen = append(*seen, r.Header.Get("Authorization"))
			if r.Header.Get("Authorization") == "Bearer revoked" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":{"username":"token:x","scope":"read"}}`))
		}))
	}
	var seen1, seen2 []string
	one, two := server(&seen1), server(&seen2)
	defer one.Close()
	defer two.Close()
	if err := saveConfig(path, Config{URL: one.URL, Token: "tokenA"}); err != nil {
		t.Fatal(err)
	}

	code, out, stderr := run(t, "tokenB\n", "login", "--url", two.URL)
	saved, _ := loadConfig(path)
	if code != exitOK || strings.Join(seen2, ",") != "Bearer tokenB" || saved.Token != "tokenB" || saved.URL != two.URL || !strings.Contains(out, "API token") {
		t.Errorf("login to another server: exit %d, it saw %v, saved %+v, %q %q; want 0, Bearer tokenB asked for and saved", code, seen2, saved, out, stderr)
	}

	seen2 = nil
	code, out, _ = run(t, "", "login", "--url", two.URL+"/")
	if code != exitOK || strings.Join(seen2, ",") != "Bearer tokenB" || strings.Contains(out, "API token") {
		t.Errorf("login again to the same server: exit %d, it saw %v, %q; want 0 and the saved token, not asked", code, seen2, out)
	}

	if err := saveConfig(path, Config{URL: two.URL, Token: "revoked"}); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = run(t, "", "login")
	if code != exitRefused || !strings.Contains(stderr, "saved token") || !strings.Contains(stderr, "--token") {
		t.Errorf("a revoked saved token: exit %d, %q; want 1 and to give a new one with --token", code, stderr)
	}
	if len(seen1) != 0 {
		t.Errorf("the first server saw %v", seen1)
	}
}

// spm login --insecure to an https address is refused before anything is
// sent: it pinned nothing, so it saved a config every later command (without
// --insecure) refused with a certificate error after saying "Signed in".
func TestLoginRefusesInsecure(t *testing.T) {
	path := isolate(t)
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"status":"success","data":{"username":"token:x","scope":"read"}}`))
	}))
	defer srv.Close()
	code, out, stderr := run(t, "", "login", "--url", srv.URL, "--token", "spm_x_y", "--insecure")
	if _, err := os.Stat(path); code != exitUsage || !strings.Contains(stderr, "--fingerprint") || err == nil || hits.Load() != 0 {
		t.Fatalf("login --insecure: exit %d, %q %q, config saved %v, %d requests; want 2, --fingerprint named, nothing saved or sent",
			code, out, stderr, err == nil, hits.Load())
	}
	t.Logf("exit %d, %s", code, strings.TrimSpace(stderr))
}

// A server that speaks another API version is named on standard error.
func TestAnotherAPIVersionIsSaid(t *testing.T) {
	isolate(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-API-Version", "2")
		_, _ = w.Write([]byte(`{"status":"success","data":{"version":"9.0.0"}}`))
	}))
	defer srv.Close()
	code, _, stderr := run(t, "", "status", "--url", srv.URL)
	if code != exitOK || !strings.Contains(stderr, "the server speaks API version 2") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

// A server that does not declare dry_run ignores it and runs the call, so the
// command sends no request asking for a preview to such a server: spm api
// refuses it, and clear without --yes says what it would do without asking.
// A server that declares it is asked, and a preview answered without dry_run
// is reported as a failure, not as a preview.
func TestAPreviewIsAskedOnlyOfAServerThatTakesIt(t *testing.T) {
	isolate(t)
	// The document of a server before dry_run: the parameter is not declared.
	old := []byte(strings.ReplaceAll(string(openAPIDocument), `"dry_run"`, `"not_dry_run"`))
	ops, err := parseOperations(old)
	if err != nil || len(ops) != len(operations) {
		t.Fatalf("the old document: %d operations (%v), want %d", len(ops), err, len(operations))
	}
	declared := 0
	for _, op := range operations {
		if op.DryRun {
			declared++
		}
	}
	if declared != 21 {
		t.Errorf("%d operations declare dry_run in the embedded document, want 21", declared)
	}
	var doc []byte
	var dryAnswer string
	var deletes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-API-Version", "1")
		switch {
		case r.URL.Path == "/api/openapi.json":
			_, _ = w.Write(doc)
		case r.Method == "DELETE":
			deletes = append(deletes, r.URL.RequestURI())
			_, _ = w.Write([]byte(dryAnswer))
		}
	}))
	defer srv.Close()

	doc, deletes = old, nil
	code, _, stderr := run(t, "", "api", "DELETE", "/api/ip-blacklist/clear-all?dry_run=true", "--url", srv.URL)
	if code != exitRefused || !strings.Contains(stderr, "does not declare dry_run") || len(deletes) != 0 {
		t.Errorf("spm api to an old server: exit %d, %q, deletes %v; want 1 and nothing sent", code, stderr, deletes)
	}
	deletes = nil
	code, _, stderr = run(t, "", "blocked-ips", "clear", "--url", srv.URL)
	if code != exitUsage || !strings.Contains(stderr, "every entry of Blocked IPs") || len(deletes) != 0 {
		t.Errorf("clear to an old server: exit %d, %q, deletes %v; want 2 and nothing sent", code, stderr, deletes)
	}
	// dry_run=false or empty asks for no preview, so nothing is checked.
	if !asksDryRun("/x?dry_run=true") || !asksDryRun("/x?dry_run=maybe") || asksDryRun("/x?dry_run=false") || asksDryRun("/x?dry_run=") || asksDryRun("/x?days=3") {
		t.Error("asksDryRun reads the query wrong")
	}

	doc, deletes, dryAnswer = openAPIDocument, nil, `{"status":"success","data":{"dry_run":true,"removed":7}}`
	code, _, stderr = run(t, "", "blocked-ips", "clear", "--url", srv.URL)
	if code != exitUsage || !strings.Contains(stderr, "this removes 7 entries of Blocked IPs") || len(deletes) != 1 || deletes[0] != "/api/ip-blacklist/clear-all?dry_run=true" {
		t.Errorf("clear to a new server: exit %d, %q, deletes %v; want 2, the count, one preview", code, stderr, deletes)
	}

	deletes, dryAnswer = nil, `{"status":"success","data":{"removed":7}}`
	code, _, stderr = run(t, "", "blocked-ips", "clear", "--url", srv.URL)
	if code != exitFailed || !strings.Contains(stderr, "may have cleared") {
		t.Errorf("a preview answered without dry_run: exit %d, %q; want 3 and the warning", code, stderr)
	}
}
