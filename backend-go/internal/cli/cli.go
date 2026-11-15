package cli

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

// Exit statuses: what a script can branch on.
const (
	exitOK      = 0 // the API answered 2xx
	exitRefused = 1 // the API answered 4xx, or the person declined
	exitUsage   = 2 // the command line or the config file is wrong; nothing was sent
	exitFailed  = 3 // the server could not be reached, its certificate did not match, or it answered 5xx
)

const usage = `spm: the Secure Proxy Manager API from a terminal.

  spm login --url https://HOST:8443 [--token TOKEN] [--fingerprint SHA256]
      Check the server's certificate, pin it once you confirm it, check the
      token, and save both to the config file (mode 0600).
  spm status [--json]
      The server's version and state.
  spm api METHOD PATH [-d JSON | -d @FILE | -d -] [--dry-run]
      Call one operation of the API, as GET /api/openapi.json describes it.
  spm api --list
      Every operation, with the token scope it needs.
  spm version

The dashboard's lists and pages, by their names there:
` + nounUsage + `
Every command takes --url, --token (or SPM_URL, SPM_TOKEN), --insecure (do
not check the certificate at all), and --config (or SPM_CONFIG).

Exit status: 0 done, 1 refused (4xx) or declined, 2 usage or config error
(nothing sent), 3 unreachable, certificate mismatch, or server error (5xx).
`

// Run is the spm command. It returns the exit status.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = fmt.Fprint(stdout, usage)
		if len(args) == 0 {
			return exitUsage
		}
		return exitOK
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "spm %s (API %s, commit %s)\n", config.AppVersion, config.APIVersion, config.GitCommit)
		return exitOK
	case "login":
		return runLogin(args[1:], stdin, stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "api":
		return runAPI(args[1:], stdin, stdout, stderr)
	case "history":
		return runHistory(args[1:], stdout, stderr)
	case "sign-in-limits":
		return runSignInLimits(args[1:], stdout, stderr)
	case "settings":
		return runSettings(args[1:], stdout, stderr)
	case "logs":
		return runLogs(args[1:], stdout, stderr)
	}
	if l, ok := listByNoun(args[0]); ok {
		return runList(l, args[1:], stdin, stdout, stderr)
	}
	fmt.Fprintf(stderr, "spm: no command %q\n\n%s", args[0], usage)
	return exitUsage
}

// common is the flags every command takes.
type common struct {
	url, token, configFile string
	insecure, json         bool
}

func newFlags(name string, stderr io.Writer, c *common) *flag.FlagSet {
	fs := flag.NewFlagSet("spm "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.url, "url", "", "server address (or SPM_URL)")
	fs.StringVar(&c.token, "token", "", "API token (or SPM_TOKEN)")
	fs.StringVar(&c.configFile, "config", "", "config file (or SPM_CONFIG)")
	fs.BoolVar(&c.insecure, "insecure", false, "do not check the server's certificate at all")
	fs.BoolVar(&c.json, "json", false, "print the API's answer as JSON")
	return fs
}

// parseInterspersed parses flags wherever they sit among the arguments, so
// "spm api GET /api/x --json" works as "spm api --json GET /api/x" does.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func (c common) config(stderr io.Writer) (string, Config, bool) {
	path := c.configFile
	if path == "" {
		p, err := configPath()
		if err != nil {
			fmt.Fprintf(stderr, "spm: no config directory: %v\n", err)
			return "", Config{}, false
		}
		path = p
	}
	file, err := loadConfig(path)
	if err != nil {
		fmt.Fprintf(stderr, "spm: %v\n", err)
		return "", Config{}, false
	}
	return path, resolve(file, c.url, c.token), true
}

// failure prints why a request did not get an answer and gives its status.
func failure(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "spm: %v\n", err)
	return exitFailed
}

// exitFor is the exit status of an API answer.
func exitFor(status int) int {
	switch {
	case status >= 200 && status < 300:
		return exitOK
	case status >= 400 && status < 500:
		return exitRefused
	default:
		return exitFailed
	}
}

// warnVersion says when the server speaks another API version than this build.
func warnVersion(stderr io.Writer, r *response) {
	if r.apiVersion != "" && r.apiVersion != config.APIVersion {
		fmt.Fprintf(stderr, "spm: the server speaks API version %s, this spm %s: update spm\n", r.apiVersion, config.APIVersion)
	}
}

func runAPI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var c common
	var data string
	var dryRun, list bool
	fs := newFlags("api", stderr, &c)
	fs.StringVar(&data, "d", "", "request body: JSON, @FILE, or - for standard input")
	fs.BoolVar(&dryRun, "dry-run", false, "print the request and send nothing")
	fs.BoolVar(&list, "list", false, "list every operation")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	if list {
		for _, op := range operations {
			fmt.Fprintf(stdout, "%-6s %-48s %-5s %s\n", op.Method, op.Path, op.Scope, op.Summary)
		}
		return exitOK
	}
	if len(pos) != 2 {
		fmt.Fprintf(stderr, "spm api: give METHOD and PATH, e.g. spm api GET /api/status\n")
		return exitUsage
	}
	method, path := strings.ToUpper(pos[0]), pos[1]
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	op, ok := findOperation(method, path)
	if !ok {
		fmt.Fprintf(stderr, "spm api: %s %s is no operation of API %s (spm api --list shows them)\n", method, strings.SplitN(path, "?", 2)[0], config.APIVersion)
		return exitUsage
	}
	if op.APIOnly != "" {
		fmt.Fprintf(stderr, "spm api: note: %s %s is for the API alone: %s\n", op.Method, op.Path, op.APIOnly)
	}
	var body []byte
	switch {
	case data == "-":
		if body, err = io.ReadAll(stdin); err != nil {
			return failure(stderr, err)
		}
	case strings.HasPrefix(data, "@"):
		if body, err = os.ReadFile(data[1:]); err != nil { // #nosec G304 -- a file the person named
			fmt.Fprintf(stderr, "spm api: %v\n", err)
			return exitUsage
		}
	case data != "":
		body = []byte(data)
	}
	if body != nil {
		if !json.Valid(body) {
			fmt.Fprintf(stderr, "spm api: the body is not JSON\n")
			return exitUsage
		}
		if op.ReadsNoBody {
			fmt.Fprintf(stderr, "spm api: %s %s reads no body\n", op.Method, op.Path)
			return exitUsage
		}
	}
	_, cfg, ok := c.config(stderr)
	if !ok {
		return exitUsage
	}
	if dryRun {
		base := strings.TrimRight(cfg.URL, "/")
		if base == "" {
			base = "(no server set)"
		}
		fmt.Fprintf(stdout, "%s %s%s\n", method, base, path)
		if body != nil {
			fmt.Fprintf(stdout, "%s\n", body)
		}
		return exitOK
	}
	cl, err := newClient(cfg, c.insecure)
	if err != nil {
		fmt.Fprintf(stderr, "spm: %v\n", err)
		return exitUsage
	}
	r, err := cl.do(method, path, body)
	if err != nil {
		return failure(stderr, err)
	}
	warnVersion(stderr, r)
	out := r.body
	if c.json || isJSON(r.body) {
		var pretty bytes.Buffer
		if json.Indent(&pretty, r.body, "", "  ") == nil {
			out = pretty.Bytes()
		}
	}
	w := stdout
	if exitFor(r.status) != exitOK {
		w = stderr
		fmt.Fprintf(stderr, "spm api: %s %s answered %d\n", method, path, r.status)
	}
	if len(out) > 0 {
		fmt.Fprintf(w, "%s\n", bytes.TrimRight(out, "\n"))
	}
	return exitFor(r.status)
}

func isJSON(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && (t[0] == '{' || t[0] == '[') && json.Valid(t)
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	var c common
	fs := newFlags("status", stderr, &c)
	if _, err := parseInterspersed(fs, args); err != nil {
		return exitUsage
	}
	_, cfg, ok := c.config(stderr)
	if !ok {
		return exitUsage
	}
	cl, err := newClient(cfg, c.insecure)
	if err != nil {
		fmt.Fprintf(stderr, "spm: %v\n", err)
		return exitUsage
	}
	r, err := cl.do("GET", "/api/status", nil)
	if err != nil {
		return failure(stderr, err)
	}
	warnVersion(stderr, r)
	if exitFor(r.status) != exitOK {
		fmt.Fprintf(stderr, "spm status: the server answered %d: %s\n", r.status, bytes.TrimSpace(r.body))
		return exitFor(r.status)
	}
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(r.body, &env); err != nil || env.Data == nil {
		fmt.Fprintf(stderr, "spm status: the answer is not the status: %s\n", bytes.TrimSpace(r.body))
		return exitFailed
	}
	if c.json {
		b, _ := json.MarshalIndent(env.Data, "", "  ")
		fmt.Fprintf(stdout, "%s\n", b)
		return exitOK
	}
	keys := make([]string, 0, len(env.Data))
	for k := range env.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(stdout, "%-22s %s\n", "server", cfg.URL)
	fmt.Fprintf(stdout, "%-22s %s (API %s)\n", "spm", config.AppVersion, config.APIVersion)
	for _, k := range keys {
		fmt.Fprintf(stdout, "%-22s %v\n", k, env.Data[k])
	}
	return exitOK
}

// peerCertificate connects to the server and returns the certificate it
// shows, and whether the system's authorities trust it for that host. It
// never turns the check off: a handshake that verifies is a trusted
// certificate, and one that fails verification hands back the certificate it
// could not verify (tls.CertificateVerificationError), which is what spm
// login shows before it pins anything.
func peerCertificate(rawURL string) (*x509.Certificate, bool, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, false, fmt.Errorf("%q is not an https URL", rawURL)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host,
		&tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
	if err == nil {
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState().PeerCertificates[0], true, nil
	}
	var unverified *tls.CertificateVerificationError
	if errors.As(err, &unverified) && len(unverified.UnverifiedCertificates) > 0 {
		return unverified.UnverifiedCertificates[0], false, nil
	}
	return nil, false, err
}

func colonHex(hex string) string {
	var parts []string
	for i := 0; i+2 <= len(hex); i += 2 {
		parts = append(parts, strings.ToUpper(hex[i:i+2]))
	}
	return strings.Join(parts, ":")
}

func runLogin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var c common
	var expect string
	fs := newFlags("login", stderr, &c)
	fs.StringVar(&expect, "fingerprint", "", "the SHA-256 fingerprint you expect, to pin it without a question")
	if _, err := parseInterspersed(fs, args); err != nil {
		return exitUsage
	}
	path, cfg, ok := c.config(stderr)
	if !ok {
		return exitUsage
	}
	if cfg.URL == "" {
		fmt.Fprintf(stderr, "spm login: give --url https://HOST:8443\n")
		return exitUsage
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	cfg.Fingerprint = ""
	in := bufio.NewReader(stdin)
	if strings.HasPrefix(cfg.URL, "https://") && !c.insecure {
		cert, trusted, err := peerCertificate(cfg.URL)
		if err != nil {
			return failure(stderr, err)
		}
		fp := fingerprintOf(cert)
		if trusted {
			fmt.Fprintf(stdout, "The certificate of %s is signed by an authority this system trusts: it is checked that way, not pinned.\n", cfg.URL)
		} else {
			fmt.Fprintf(stdout, "The certificate of %s is not signed by an authority this system trusts.\n", cfg.URL)
			fmt.Fprintf(stdout, "  subject  %s\n  issuer   %s\n  valid    %s to %s\n  SHA-256  %s\n",
				cert.Subject, cert.Issuer, cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"), colonHex(fp))
			switch {
			case expect != "":
				if strings.ToLower(strings.ReplaceAll(expect, ":", "")) != fp {
					fmt.Fprintf(stderr, "spm login: the certificate's fingerprint is not the one given with --fingerprint; nothing saved\n")
					return exitRefused
				}
			default:
				fmt.Fprintf(stdout, "Compare the fingerprint with the one the server's console shows. Pin it? [y/N] ")
				answer, _ := in.ReadString('\n')
				if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
					fmt.Fprintf(stderr, "spm login: not pinned; nothing saved\n")
					return exitRefused
				}
			}
			cfg.Fingerprint = fp
		}
	}
	if cfg.Token == "" {
		fmt.Fprintf(stdout, "API token (Settings > Admin and backup > API tokens): ")
		line, _ := in.ReadString('\n')
		cfg.Token = strings.TrimSpace(line)
	}
	if cfg.Token == "" {
		fmt.Fprintf(stderr, "spm login: no token\n")
		return exitUsage
	}
	cl, err := newClient(cfg, c.insecure)
	if err != nil {
		fmt.Fprintf(stderr, "spm: %v\n", err)
		return exitUsage
	}
	r, err := cl.do("GET", "/api/session", nil)
	if err != nil {
		return failure(stderr, err)
	}
	warnVersion(stderr, r)
	if r.status != 200 {
		fmt.Fprintf(stderr, "spm login: the server refused the token (%d); nothing saved\n", r.status)
		return exitFor(r.status)
	}
	var s struct {
		Data struct {
			Username string `json:"username"`
			Scope    string `json:"scope"`
		} `json:"data"`
	}
	_ = json.Unmarshal(r.body, &s)
	if err := saveConfig(path, cfg); err != nil {
		return failure(stderr, err)
	}
	fmt.Fprintf(stdout, "Signed in to %s as %s (scope %s). Saved to %s.\n", cfg.URL, s.Data.Username, s.Data.Scope, path)
	return exitOK
}
