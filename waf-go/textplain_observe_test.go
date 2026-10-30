package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"secure-proxy-waf/internal/engine"
)

// Injection and target-category matches in a text/plain body are recorded with
// no score: a pasted snippet with <script> and a command passes and the
// rules still show in the verdict. The same payload in a form blocks.
func TestTextPlainBodyObservesInjectionCategories(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	body := "Repro:\n<script>alert(document.cookie)</script>\nthen run: x; cat /tmp/out\n" +
		"config is in .env and .aws/credentials, db at 192.168.1.100:5432, query: name = 'a' or 1=1 --\n"
	post := func(ct, b, ip string) verdict {
		r := httptest.NewRequest("POST", "http://paste.example.com/api", strings.NewReader(b))
		r.Header.Set("Content-Type", ct)
		return runReqmod(t, r, ip)
	}
	v := post("text/plain; charset=utf-8", body, "198.51.100.170")
	if v.Action != "allow" || v.Score != 0 {
		t.Errorf("text/plain snippet: %s, want allow with score 0", v)
	}
	if !strings.Contains(v.Rules, "XSS-") {
		t.Errorf("text/plain snippet: rules [%s], want the XSS match recorded", v.Rules)
	}
	if v := post("application/x-www-form-urlencoded", "comment="+strings.ReplaceAll(body, "\n", " "), "198.51.100.171"); v.Action != "block" {
		t.Errorf("the same payload in a form: %s, want block", v)
	}
}
