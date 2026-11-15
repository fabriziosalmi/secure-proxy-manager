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
