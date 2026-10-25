package netguard

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestIsInternalTarget(t *testing.T) {
	own := []netip.Prefix{netip.MustParsePrefix("172.18.0.0/16")}
	cases := []struct {
		ip       string
		internal bool
		why      string
	}{
		{"127.0.0.1", true, "loopback: the backend itself"},
		{"::1", true, "IPv6 loopback"},
		{"169.254.169.254", true, "cloud metadata, link-local"},
		{"fe80::1", true, "IPv6 link-local"},
		{"0.0.0.0", true, "unspecified"},
		{"0.1.2.3", true, "0.0.0.0/8"},
		{"224.0.0.1", true, "multicast"},
		{"172.18.0.5", true, "a container on the backend's own network (the WAF, the proxy)"},
		{"::ffff:127.0.0.1", true, "IPv4-mapped loopback"},
		{"192.168.1.20", false, "a self-hosted Gotify on the LAN"},
		{"10.0.0.7", false, "a LAN service in 10/8"},
		{"100.101.102.103", false, "a Tailscale address"},
		{"172.19.0.5", false, "a private network the backend is not on"},
		{"8.8.8.8", false, "a public address"},
	}
	for _, c := range cases {
		if got := IsInternalTarget(net.ParseIP(c.ip), own); got != c.internal {
			t.Errorf("IsInternalTarget(%s) = %v, want %v (%s)", c.ip, got, c.internal, c.why)
		}
	}
}

func TestCheckNotifyURL(t *testing.T) {
	ok := []string{
		"https://hooks.example.com/x",
		"http://192.168.1.20:8080/message",
		"https://ntfy.sh",
	}
	for _, u := range ok {
		if err := CheckNotifyURL(u); err != nil {
			t.Errorf("CheckNotifyURL(%q) = %v, want nil", u, err)
		}
	}
	bad := map[string]string{
		"file:///etc/passwd":                    "http or https",
		"gopher://x":                            "http or https",
		"hooks.example.com/x":                   "http or https",
		"https://":                              "http or https",
		"https://user:pass@hooks.example.com/x": "user name or password",
		"http://localhost:5000/api":             "this host",
		"http://127.0.0.1:5000/api":             "loopback",
		"http://[::1]/x":                        "loopback",
		"http://169.254.169.254/latest":         "link-local",
	}
	for u, want := range bad {
		err := CheckNotifyURL(u)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckNotifyURL(%q) = %v, want an error naming %q", u, err, want)
		}
	}
}

// The client checks the address it is about to dial, so a name that resolves
// to loopback is refused even though its URL passed the shape check.
func TestNotifyClientRefusesAnInternalTarget(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	_, err := NotifyClient(2*time.Second).Post(srv.URL, "application/json", strings.NewReader("{}"))
	var blocked *BlockedTargetError
	if !errors.As(err, &blocked) {
		t.Fatalf("posting to %s: err = %v, want a BlockedTargetError", srv.URL, err)
	}
	if hit {
		t.Error("the request reached the loopback server")
	}
}

func TestNotifyClientDoesNotFollowRedirects(t *testing.T) {
	c := NotifyClient(time.Second)
	if c.CheckRedirect == nil || c.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("the notification client follows redirects")
	}
}
