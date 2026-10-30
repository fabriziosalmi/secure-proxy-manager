package main

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"secure-proxy-waf/internal/engine"
)

// A CONNECT carries only host:port, so only the SSRF rules are matched on
// it: tool and command names in a host name are not an attack. The same
// names in a request the WAF can see still are.
func TestConnectIsMatchedOnlyForSSRF(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	verdict := func(raw, ip string) verdict {
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return runReqmod(t, r, ip)
	}
	for i, host := range []string{"ifconfig.me", "ipconfig.io", "www.metasploit.com"} {
		v := verdict("CONNECT "+host+":443 HTTP/1.1\r\nHost: "+host+":443\r\n\r\n", "198.51.100."+itoa(150+i))
		if v.Action != "allow" {
			t.Errorf("CONNECT %s: %s, want allow", host, v)
		}
	}
	// The metadata IP itself is a LAN host, skipped by the WAF and refused
	// by Squid (direct_ip); its name reaches the WAF and is SSRF.
	if v := verdict("CONNECT metadata.google.internal:443 HTTP/1.1\r\nHost: metadata.google.internal:443\r\n\r\n", "198.51.100.160"); v.Action != "block" {
		t.Errorf("CONNECT to the metadata name: %s, want block", v)
	}
	if v := verdict("GET http://x.example/run?c=ipconfig HTTP/1.1\r\nHost: x.example\r\n\r\n", "198.51.100.161"); v.Action != "block" {
		t.Errorf("ipconfig in a visible request: %s, want block", v)
	}
}
