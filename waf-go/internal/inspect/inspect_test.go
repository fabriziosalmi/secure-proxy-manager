package inspect

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"

	"secure-proxy-waf/internal/crs"
	"secure-proxy-waf/internal/engine"
)

var crsPL1 *crs.Engine

func TestMain(m *testing.M) {
	engine.BuildPrefilter()
	c, err := crs.New(crs.Options{Paranoia: 1})
	if err != nil {
		panic(err)
	}
	crsPL1 = c
	m.Run()
}

func req(t *testing.T, raw string) *http.Request {
	t.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func post(ct, body string) string {
	return "POST http://shop.example/p HTTP/1.1\r\nHost: shop.example\r\nContent-Type: " + ct +
		"\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body
}

func newEngine() *engine.Engine { return engine.New(engine.Config{BlockThreshold: 10}) }

// CRS runs last and only when it has something to add: not without a CRS
// engine, not on a CONNECT, not after the spm score has blocked.
func TestRunCRSRunsOnlyWhenItCanChangeTheVerdict(t *testing.T) {
	const php = "GET http://shop.example/s?x=<?php%20system($_GET['c']);%20?> HTTP/1.1\r\nHost: shop.example\r\n\r\n"
	in, _ := Evaluate(newEngine(), nil, nil, req(t, php), "192.0.2.1")
	if in.CRS != nil || in.Blocked() {
		t.Errorf("legacy: CRS=%v blocked=%v", in.CRS, in.Blocked())
	}
	in, _ = Evaluate(newEngine(), crsPL1, nil, req(t, php), "192.0.2.2")
	if in.CRS == nil || !in.CRS.Blocked || !in.Blocked() {
		t.Fatalf("hybrid: CRS=%+v", in.CRS)
	}
	in, _ = Evaluate(newEngine(), crsPL1, nil, req(t, "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n"), "192.0.2.3")
	if in.CRS != nil {
		t.Error("CRS ran on a CONNECT")
	}
	in, _ = Evaluate(newEngine(), crsPL1, nil, req(t, "GET http://shop.example/s?q=<script>alert(1)</script> HTTP/1.1\r\nHost: shop.example\r\n\r\n"), "192.0.2.4")
	if !in.Eng.Blocked(in.Score) || in.CRS != nil {
		t.Errorf("after an spm block: score=%d CRS=%v", in.Score, in.CRS)
	}
	if _, lan := Evaluate(newEngine(), crsPL1, nil, req(t, "GET http://192.168.1.10/ HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n"), "192.0.2.5"); !lan {
		t.Error("a LAN destination was inspected")
	}
}

// CRS reads the body the spm scan read, or, for a content type the spm
// scan skips, reads it itself; either way the request still carries the
// whole body for the destination.
func TestRunCRSReadsTheBodyAndLeavesItWhole(t *testing.T) {
	for _, c := range []struct{ ct, body string }{
		{"application/x-www-form-urlencoded", "a=1&x=<?php%20system($_GET['c']);%20?>"},
		{"application/octet-stream", "x=<?php system($_GET['c']); ?>\x00\x01"},
	} {
		r := req(t, post(c.ct, c.body))
		in := &Inspection{Eng: newEngine(), CRSEng: crsPL1, RawURL: r.URL.String(), ClientIP: "192.0.2.9"}
		in.Scan(r)
		in.RunCRS(r)
		if in.CRS == nil {
			t.Fatalf("%s: CRS did not run", c.ct)
		}
		rest, _ := io.ReadAll(r.Body)
		if string(rest) != c.body {
			t.Errorf("%s: forwarded body %q, want %q", c.ct, rest, c.body)
		}
	}
	if b := peekBody(req(t, "GET http://shop.example/ HTTP/1.1\r\nHost: shop.example\r\n\r\n")); b != nil {
		t.Errorf("a GET without a body peeked %q", b)
	}
}

// The verdict lists what decided first: CRS's rules and families when CRS
// blocked alone, the spm ones otherwise.
func TestVerdictOrder(t *testing.T) {
	in := &Inspection{Eng: newEngine()}
	in.Add(engine.MatchResult{RuleID: "CMDi-008", Category: "COMMAND_INJECTION", Score: 5})
	in.CRS = &crs.Result{Blocked: true, Score: 15, Rules: []string{"933100", "933160"}}
	ids, cats := in.Verdict()
	if strings.Join(ids, ",") != "CRS-933100,CRS-933160,CMDi-008" || cats[0] != "CRS_PHP" {
		t.Errorf("CRS alone blocked: %v %v", ids, cats)
	}
	in.Add(engine.MatchResult{RuleID: "XSS-001", Category: "XSS_ATTACKS", Score: 10})
	ids, cats = in.Verdict()
	if ids[0] != "CMDi-008" || cats[0] != "COMMAND_INJECTION" || cats[len(cats)-1] != "CRS_PHP" {
		t.Errorf("spm blocked too: %v %v", ids, cats)
	}
	in.CRS = &crs.Result{}
	if ids, _ = in.Verdict(); len(ids) != 2 {
		t.Errorf("CRS without rules added %v", ids)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
