package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
