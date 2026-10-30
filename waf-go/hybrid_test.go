package main

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/go-icap/icap"

	"secure-proxy-waf/internal/crs"
	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/inspect"
)

// hybridCRS is a CRS half built once for these tests, whatever WAF_ENGINE
// the test binary started with.
func hybridCRS(t *testing.T) *crs.Engine {
	t.Helper()
	c, err := crs.New(crs.Options{Paranoia: 1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func icapReq(r *http.Request, clientIP string) *icap.Request {
	ireq := &icap.Request{Request: r, Header: squidHeader()}
	ireq.Header.Set("X-Client-Ip", clientIP)
	return ireq
}

func readReq(t *testing.T, raw string) *http.Request {
	t.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A PHP injection the spm rules only observe is blocked by the CRS half, and
// the block names CRS: the CRS-<id> rules, the CRS_PHP family on the block
// page. Under legacy the same request passes, as it did before the hybrid.
func TestHybridBlocksWhatOnlyCRSCatches(t *testing.T) {
	const u = "http://shop.example/s?x=<?php%20system($_GET['c']);%20?>"
	withEngine(t, engine.Config{BlockThreshold: 10})

	withCRS(t, nil)
	if v := runReqmod(t, httptest.NewRequest("GET", u, nil), "198.51.100.230"); v.Action != "allow" {
		t.Fatalf("legacy: %s, want allow", v)
	}

	withCRS(t, hybridCRS(t))
	w := &mockResponseWriter{}
	ireq := icapReq(httptest.NewRequest("GET", u, nil), "198.51.100.231")
	handleReqmod(w, ireq)
	resp, ok := w.resp.(*http.Response)
	if !ok || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("hybrid: ICAP %d, want a 403 block page", w.code)
	}
	page, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(page), "Category: <b>CRS_PHP</b>") {
		t.Errorf("block page does not name the CRS family: %s", page)
	}
	v := runReqmod(t, httptest.NewRequest("GET", u, nil), "198.51.100.232")
	if v.Action != "block" || !strings.Contains(v.Rules, "CRS-933") {
		t.Errorf("hybrid: %s, want a block with CRS-933xxx rules", v)
	}
}

// A CONNECT is a host name and a port: CRS does not run on it.
func TestHybridLeavesConnectToTheSPMEngine(t *testing.T) {
	e := engine.New(engine.Config{BlockThreshold: 10})
	c := hybridCRS(t)
	in, _ := inspect.Evaluate(e, c, nil, readReq(t, "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n"), "198.51.100.233")
	if in.CRS != nil {
		t.Errorf("CRS ran on a CONNECT: %+v", *in.CRS)
	}
	in, _ = inspect.Evaluate(e, c, nil, readReq(t, "GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n"), "198.51.100.233")
	if in.CRS == nil {
		t.Error("CRS did not run on a GET")
	}
}

// Request framing as net/http leaves it: a chunked POST has its
// Transfer-Encoding moved out of the header map. CRS must still see it, or
// every chunked POST scores 920180 (POST without Content-Length and
// Transfer-Encoding).
func TestHybridSeesTheFramingOfAChunkedPost(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withCRS(t, hybridCRS(t))
	raw := "POST http://api.example/v1/items HTTP/1.1\r\nHost: api.example\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"b\r\n{\"name\":\"a\"}\r\n0\r\n\r\n"
	v := runReqmod(t, readReq(t, raw), "198.51.100.234")
	if v.Action != "allow" || strings.Contains(v.Rules, "920180") {
		t.Errorf("chunked POST: %s, want allow without 920180", v)
	}
}

// Bodies that are not a form: NDJSON log shipping, a Sentry envelope, a
// pretty-printed +json document, a binary upload. Parsed as urlencoded, as
// Coraza does with what CRS asks it to parse, each line break lands in an
// argument name and 921150 blocks on its own.
func TestHybridPassesBodiesThatAreNotForms(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withCRS(t, hybridCRS(t))
	for i, c := range []struct{ ct, body string }{
		{"application/x-ndjson", "{\"index\":{\"_index\":\"logs\"}}\n{\"msg\":\"GET /health 200\",\"level\":\"info\"}\n"},
		{"application/x-sentry-envelope", "{\"event_id\":\"9ec79c33ec9942ab8353589fcb2e04dc\",\"sent_at\":\"2026-10-29T08:00:00Z\"}\n{\"type\":\"event\"}\n{\"message\":\"TypeError: x is undefined\"}\n"},
		{"application/vnd.api+json", "{\n  \"data\": {\n    \"type\": \"articles\",\n    \"id\": \"1\"\n  }\n}\n"},
		{"application/atom+xml", "<?xml version=\"1.0\"?>\n<feed xmlns=\"http://www.w3.org/2005/Atom\">\n  <title>News</title>\n</feed>\n"},
		{"application/octet-stream", "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\r\n=\x00\x01"},
	} {
		raw := "POST http://ingest.example/api/1/envelope/ HTTP/1.1\r\nHost: ingest.example\r\nContent-Type: " + c.ct +
			"\r\nContent-Length: " + itoa(len(c.body)) + "\r\n\r\n" + c.body
		if v := runReqmod(t, readReq(t, raw), "198.51.100."+itoa(235+i)); v.Action != "allow" {
			t.Errorf("%s: %s, want allow", c.ct, v)
		}
	}
	// A form body is still parsed into arguments.
	form := "user=a&x=<?php%20system($_GET['c']);%20?>&p=1234"
	raw := "POST http://shop.example/login HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + itoa(len(form)) + "\r\n\r\n" + form
	if v := runReqmod(t, readReq(t, raw), "198.51.100.240"); v.Action != "block" || !strings.Contains(v.Rules, "CRS-933") {
		t.Errorf("form body: %s, want a CRS-933xxx block", v)
	}
}

// Data leak prevention, financial data and cloud secrets only observe in the
// hybrid: the match is recorded with no score. WAF_OBSERVE_CATEGORIES=none
// makes them block again.
func TestObserveCategoriesRecordWithoutBlocking(t *testing.T) {
	const body = `{"note":"deploy key AKIAIOSFODNN7EXAMPLE"}`
	raw := "POST http://paste.example/api HTTP/1.1\r\nHost: paste.example\r\nContent-Type: application/json\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	withCRS(t, hybridCRS(t))
	for i, c := range []struct {
		env, want string
	}{
		{"", "allow"},
		{"none", "block"},
	} {
		_, _, observe, err := selectEngine(func(k string) string {
			if k == "WAF_OBSERVE_CATEGORIES" {
				return c.env
			}
			return ""
		})
		if err != nil {
			t.Fatal(err)
		}
		withEngine(t, engine.Config{BlockThreshold: 10, ObserveCategories: observe})
		v := runReqmod(t, readReq(t, raw), "198.51.100."+itoa(241+i))
		if v.Action != c.want || !strings.Contains(v.Rules, "CLOUD-001") {
			t.Errorf("WAF_OBSERVE_CATEGORIES=%q: %s, want %s with CLOUD-001 recorded", c.env, v, c.want)
		}
		if c.want == "allow" && v.Score != 0 {
			t.Errorf("observe-only match scored %d", v.Score)
		}
	}
}

func TestSelectEngine(t *testing.T) {
	env := func(kv ...string) func(string) string {
		return func(k string) string {
			for i := 0; i < len(kv); i += 2 {
				if kv[i] == k {
					return kv[i+1]
				}
			}
			return ""
		}
	}
	name, c, observe, err := selectEngine(env())
	if err != nil || name != "hybrid" || c == nil || strings.Join(observe, ",") != "DATA_LEAK_PREVENTION,FINANCIAL_DATA,CLOUD_SECRETS" {
		t.Errorf("default: %s crs=%v observe=%v err=%v", name, c != nil, observe, err)
	}
	name, c, observe, err = selectEngine(env("WAF_ENGINE", " Legacy "))
	if err != nil || name != "legacy" || c != nil || observe != nil {
		t.Errorf("legacy: %s crs=%v observe=%v err=%v", name, c != nil, observe, err)
	}
	_, _, observe, _ = selectEngine(env("WAF_OBSERVE_CATEGORIES", "FINANCIAL_DATA, ,SSRF"))
	if strings.Join(observe, ",") != "FINANCIAL_DATA,SSRF" {
		t.Errorf("explicit list: %v", observe)
	}
	if _, _, _, err = selectEngine(env("WAF_ENGINE", "coraza")); err == nil {
		t.Error("an unknown WAF_ENGINE was accepted")
	}

	// A CRS that does not load is an error, never a quiet fall back to the
	// spm engine alone.
	prev := newCRS
	t.Cleanup(func() { newCRS = prev })
	newCRS = func(crs.Options) (*crs.Engine, error) { return nil, errors.New("rule file missing") }
	if _, c, _, err = selectEngine(env()); err == nil || c != nil {
		t.Errorf("a failed CRS load gave crs=%v err=%v", c != nil, err)
	}
	if _, _, _, err = selectEngine(env("WAF_ENGINE", "legacy")); err != nil {
		t.Errorf("legacy does not need CRS: %v", err)
	}
}

// The WAF does not start on an engine it cannot run: the process exits 1 and
// says why. Run as a child, since the check is at start-up.
func TestUnknownEngineStopsTheWAF(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "WAF_ENGINE=coraza")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("exit: %v, want status 1\n%s", err, out)
	}
	if !strings.Contains(string(out), "WAF not started") || !strings.Contains(string(out), `WAF_ENGINE=\"coraza\"`) {
		t.Errorf("the reason is not in the output:\n%s", out)
	}
}

// The engine is part of the ruleset identity: a switch between hybrid and
// legacy invalidates Squid's cached OPTIONS, and /health and /metrics say
// which engine runs.
func TestEngineIsReported(t *testing.T) {
	prevName, prevBase := wafEngine, istagBase
	t.Cleanup(func() { wafEngine, istagBase = prevName, prevBase; initISTag() })

	wafEngine = "hybrid"
	initISTag()
	hybridTag := istagBase
	wafEngine = "legacy"
	initISTag()
	if istagBase == hybridTag {
		t.Error("the ISTag is the same for hybrid and legacy")
	}

	w := httptest.NewRecorder()
	(&MgmtHandlers{}).HealthHandler(w, httptest.NewRequest("GET", "/health", nil))
	if !strings.Contains(w.Body.String(), `"engine":"legacy"`) {
		t.Errorf("/health: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	(&MgmtHandlers{}).MetricsHandler(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), `waf_engine_info{engine="legacy",regex="`+engine.RegexEngine()+`"} 1`) {
		t.Error("/metrics has no waf_engine_info for legacy")
	}
}

// An unknown WAF_REGEX_ENGINE stops the WAF with the reason, as an unknown
// WAF_ENGINE does: it does not run an engine the operator did not choose.
func TestUnknownRegexEngineStopsTheWAF(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "WAF_REGEX_ENGINE=pcre")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("exit: %v, want status 1\n%s", err, out)
	}
	if !strings.Contains(string(out), "WAF not started") || !strings.Contains(string(out), `WAF_REGEX_ENGINE=\"pcre\"`) {
		t.Errorf("the reason is not in the output:\n%s", out)
	}
}

// /health names the regex engine in force.
func TestRegexEngineIsReported(t *testing.T) {
	w := httptest.NewRecorder()
	(&MgmtHandlers{}).HealthHandler(w, httptest.NewRequest("GET", "/health", nil))
	if !strings.Contains(w.Body.String(), `"regex_engine":"`+engine.RegexEngine()+`"`) {
		t.Errorf("/health: %s", w.Body.String())
	}
}

// /categories says which categories only observe, so an enabled category
// is not taken for a blocking one.
func TestCategoriesReportObserveOnly(t *testing.T) {
	withEngine(t, engine.Config{ObserveCategories: []string{"FINANCIAL_DATA"}})
	w := httptest.NewRecorder()
	(&MgmtHandlers{}).CategoriesHandler(w, httptest.NewRequest("GET", "/categories", nil))
	body := w.Body.String()
	if !strings.Contains(body, `"name":"FINANCIAL_DATA","rules":`) || !strings.Contains(body, `"enabled":true,"observe":true}`) {
		t.Errorf("FINANCIAL_DATA not reported as observe-only: %s", body)
	}
	if strings.Count(body, `"observe":true`) != 1 {
		t.Errorf("want exactly one observe-only category: %s", body)
	}
}
