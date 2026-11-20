package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

// realBackend builds cmd/server, starts it on a free loopback port with its
// own database and directories, and returns its address and admin password.
// It runs the backend the release ships, not a test router.
func realBackend(t *testing.T) (string, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("builds and runs the backend")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "spm-server")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "../../cmd/server")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the backend: %v\n%s", err, out)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	for _, d := range []string{"data", "config", "secrets", "logs"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const password = "Cli-test-passw0rd!"
	cmd := exec.Command(bin)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + dir,
		fmt.Sprintf("PORT=%d", port),
		"DATABASE_PATH=" + filepath.Join(dir, "data", "db.sqlite"),
		"CONFIG_DIR=" + filepath.Join(dir, "config"),
		"PROXY_SECRETS_DIR=" + filepath.Join(dir, "secrets"),
		"LOG_PATH=" + filepath.Join(dir, "logs", "access.log"),
		"DNS_LOG_PATH=" + filepath.Join(dir, "logs", "dns.log"),
		"WAF_POLICY_FILE=" + filepath.Join(dir, "config", "waf_policy.json"),
		"SPM_SERVICE_TOKEN_FILE=" + filepath.Join(dir, "secrets", "service_token"),
		"BASIC_AUTH_USERNAME=admin", "BASIC_AUTH_PASSWORD=" + password,
		"SECRET_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	logf, _ := os.Create(filepath.Join(dir, "server.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		logf.Close()
	})
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	for i := 0; i < 100; i++ {
		if r, err := http.Get(base + "/readyz"); err == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				return base, password
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "server.log"))
	t.Fatalf("the backend did not become ready:\n%s", b)
	return "", ""
}

// tlsFront is a TLS server with its own self-signed certificate in front of
// the backend, as nginx is in the shipped stack. Each gets a certificate made
// here: httptest's default one is the same for every server, so two fronts
// would show one fingerprint and the pin could not tell them apart.
func tlsFront(t *testing.T, backend string) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"spm cli test"}, CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(backend)
	srv := httptest.NewUnstartedServer(httputil.NewSingleHostReverseProxy(u))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// newToken makes an API token of scope with the admin password.
func newToken(t *testing.T, backend, password, name, scope string) string {
	t.Helper()
	req, _ := http.NewRequest("POST", backend+"/api/tokens", strings.NewReader(fmt.Sprintf(`{"name":%q,"scope":%q,"expires_in_days":1}`, name, scope)))
	req.SetBasicAuth("admin", password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "spm")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var out struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	_ = json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != http.StatusCreated || out.Data.Token == "" {
		t.Fatalf("make token %s: %d", name, r.StatusCode)
	}
	return out.Data.Token
}

// spm against the backend the release ships, behind a TLS server whose
// certificate no authority signed: login pins it only once confirmed, the
// calls go through with the token, a 4xx and a scope refusal exit 1, and a
// server showing another certificate is refused.
func TestSpmAgainstTheRealBackend(t *testing.T) {
	path := isolate(t)
	backend, password := realBackend(t)
	front := tlsFront(t, backend)
	write := newToken(t, backend, password, "cli-write", "write")
	read := newToken(t, backend, password, "cli-read", "read")

	// Declined: nothing saved.
	if code, _, stderr := run(t, "n\n", "login", "--url", front.URL, "--token", write); code != exitRefused || !strings.Contains(stderr, "not pinned") {
		t.Fatalf("declined login: exit %d, %q", code, stderr)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a declined login saved the config")
	}
	// A wrong expected fingerprint: refused, nothing saved.
	if code, _, _ := run(t, "", "login", "--url", front.URL, "--token", write, "--fingerprint", strings.Repeat("ab", 32)); code != exitRefused {
		t.Fatalf("wrong --fingerprint: exit %d, want 1", code)
	}
	// Confirmed: the fingerprint of the front's certificate is pinned.
	code, out, stderr := run(t, "y\n", "login", "--url", front.URL, "--token", write)
	if code != exitOK || !strings.Contains(out, "scope write") {
		t.Fatalf("login: exit %d, %q %q", code, out, stderr)
	}
	saved, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := fingerprintOf(front.Certificate()); saved.Fingerprint != want || saved.Token != write {
		t.Fatalf("saved %+v, want fingerprint %s and the write token", saved, want)
	}

	// The status, from the backend that answered.
	code, out, _ = run(t, "", "status", "--json")
	var st map[string]any
	if code != exitOK || json.Unmarshal([]byte(out), &st) != nil || st["version"] != config.AppVersion {
		t.Fatalf("status: exit %d, %s", code, out)
	}

	// A write, a read of it, and a body the API refuses.
	if code, _, stderr := run(t, "", "api", "POST", "/api/ip-blacklist", "-d", `{"ip":"203.0.113.9","description":"from spm"}`); code != exitOK {
		t.Fatalf("add: exit %d, %s", code, stderr)
	}
	if code, out, _ := run(t, "", "api", "GET", "/api/ip-blacklist?search=203.0.113.9"); code != exitOK || !strings.Contains(out, "from spm") {
		t.Fatalf("list: exit %d, %s", code, out)
	}
	if code, _, stderr := run(t, "", "api", "POST", "/api/ip-blacklist", "-d", `{}`); code != exitRefused || !strings.Contains(stderr, "answered 400") {
		t.Fatalf("refused body: exit %d, %s", code, stderr)
	}
	// A read token may not write: 403, exit 1.
	if code, _, stderr := run(t, "", "api", "POST", "/api/ip-blacklist", "-d", `{"ip":"203.0.113.10"}`, "--token", read); code != exitRefused || !strings.Contains(stderr, "answered 403") {
		t.Fatalf("read token writing: exit %d, %s", code, stderr)
	}

	// Another server certificate in front of the same backend: refused.
	other := tlsFront(t, backend)
	if fingerprintOf(other.Certificate()) == saved.Fingerprint {
		t.Fatal("the second front shows the same certificate: the check below would prove nothing")
	}
	code, _, stderr = run(t, "", "status", "--url", other.URL)
	if code != exitFailed || !strings.Contains(stderr, "not the one pinned") {
		t.Fatalf("other certificate: exit %d, %q", code, stderr)
	}
}

// The curated commands, by the dashboard's names, against the backend the
// release ships: each list's add, list, remove, clear (refused without
// --yes), import and export; the default-deny allowlist with subdomains; the
// configuration history; settings; sign-in limits; the access log.
func TestCuratedCommandsAgainstTheRealBackend(t *testing.T) {
	isolate(t)
	backend, password := realBackend(t)
	t.Setenv("SPM_URL", backend)
	t.Setenv("SPM_TOKEN", newToken(t, backend, password, "cli-curated", "write"))
	expect := func(want int, contains string, args ...string) string {
		t.Helper()
		code, out, stderr := run(t, "", args...)
		if code != want || (contains != "" && !strings.Contains(out+stderr, contains)) {
			t.Fatalf("spm %s: exit %d, %q %q; want %d and %q", strings.Join(args, " "), code, out, stderr, want, contains)
		}
		return out
	}
	expect(exitOK, "", "blocked-ips", "add", "203.0.113.9", "--note", "scanner")
	expect(exitOK, "scanner", "blocked-ips", "list", "--search", "203.0.113")
	expect(exitOK, "Removed 203.0.113.9 from Blocked IPs", "blocked-ips", "remove", "203.0.113.9")
	expect(exitRefused, "is not on Blocked IPs", "blocked-ips", "remove", "203.0.113.9")
	expect(exitOK, "", "blocked-ips", "add", "203.0.113.10")
	// Without --yes the server previews the clear, and nothing goes.
	expect(exitUsage, "this removes 1 entry of Blocked IPs; add --yes", "blocked-ips", "clear")
	expect(exitOK, `"dry_run": true`, "api", "DELETE", "/api/ip-blacklist/clear-all?dry_run=true")
	expect(exitOK, "203.0.113.10", "blocked-ips", "list")
	expect(exitOK, "Removed 1 entries from Blocked IPs", "blocked-ips", "clear", "--yes")

	f := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(f, []byte("ads.example.com\ntracker.example.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expect(exitOK, "", "blocked-domains", "import", f)
	out := expect(exitOK, "", "blocked-domains", "export")
	if !strings.Contains(out, "ads.example.com") || !strings.Contains(out, "tracker.example.net") {
		t.Fatalf("export after import: %q", out)
	}
	expect(exitOK, "paste", "blocked-domains", "sources")
	// A blocked wildcard is removed by its name and as it is written: the
	// search sent is the name, which every stored form contains. The output
	// names the entry removed, as it is written on the list.
	expect(exitOK, "", "blocked-domains", "add", "*.ads.example.org")
	expect(exitOK, "Removed *.ads.example.org from Blocked domains", "blocked-domains", "remove", "ads.example.org")
	expect(exitOK, "", "blocked-domains", "add", "*.ads.example.org")
	expect(exitOK, "Removed *.ads.example.org from Blocked domains", "blocked-domains", "remove", "*.ads.example.org")
	expect(exitOK, "", "domain-exceptions", "add", "cdn.example.net")
	expect(exitOK, "Removed cdn.example.net from Domain exceptions", "domain-exceptions", "remove", "*.cdn.example.net")
	expect(exitOK, "", "ip-exceptions", "add", "198.51.100.5")
	expect(exitOK, "198.51.100.5", "ip-exceptions", "list")

	expect(exitOK, "", "allowlist", "add", "example.com", "--subdomains")
	expect(exitOK, ".example.com", "allowlist", "list")
	expect(exitOK, "Removed .example.com from Default-deny allowlist", "allowlist", "remove", "example.com")
	// Both forms on the list, the wider one newer: remove example.com takes
	// the entry written so, not the newest loose match.
	expect(exitOK, "", "allowlist", "add", "example.com")
	expect(exitOK, "", "allowlist", "add", "example.com", "--subdomains")
	expect(exitOK, "Removed example.com from Default-deny allowlist", "allowlist", "remove", "example.com")
	var left []map[string]any
	if err := json.Unmarshal([]byte(expect(exitOK, "", "allowlist", "list", "--json")), &left); err != nil || len(left) != 1 || left[0]["entry"] != ".example.com" {
		t.Fatalf("after removing example.com with .example.com newer: %v (%v); want only .example.com", left, err)
	}
	expect(exitOK, "", "allowlist", "remove", ".example.com")
	// "*.example.com" names the entry with subdomains, though the backend
	// reads "*" in a search as a literal character.
	expect(exitOK, "", "allowlist", "add", "example.com", "--subdomains")
	expect(exitOK, "Removed .example.com from Default-deny allowlist", "allowlist", "remove", "*.example.com")
	expect(exitUsage, "has no import", "allowlist", "import", f)

	expect(exitOK, "", "settings", "set", "log_retention_days", "45")
	expect(exitOK, "45", "settings", "get", "log_retention_days")
	expect(exitRefused, "no setting", "settings", "get", "no_such_setting")

	expect(exitOK, "", "history", "take", "--note", "from spm")
	expect(exitOK, "from spm", "history", "list")
	expect(exitUsage, "add --yes", "history", "restore", "1")
	expect(exitOK, "", "history", "diff", "1")

	expect(exitOK, "", "sign-in-limits", "list")
	expect(exitRefused, "404", "sign-in-limits", "clear", "192.0.2.1")
	expect(exitOK, "", "logs", "--limit", "5")
	expect(exitUsage, "no verb", "blocked-ips", "frobnicate")
}
