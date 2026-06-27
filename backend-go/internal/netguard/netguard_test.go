package netguard

import (
	"net"
	"testing"
)

// IsBlockedIP is the shared SSRF/blacklist kill-switch. A regression here
// silently opens server-side request forgery or lets a LAN range poison a
// source blacklist, so the matrix below pins every class it must cover —
// including the IPv4-mapped-IPv6 unmap path that is the classic bypass.
func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
		why     string
	}{
		// Loopback
		{"127.0.0.1", true, "IPv4 loopback"},
		{"127.255.255.254", true, "IPv4 loopback range"},
		{"::1", true, "IPv6 loopback"},
		// RFC1918 private
		{"10.0.0.1", true, "10/8"},
		{"172.16.0.1", true, "172.16/12 low"},
		{"172.31.255.255", true, "172.16/12 high"},
		{"192.168.1.1", true, "192.168/16"},
		{"fd00::1", true, "IPv6 ULA private"},
		// Link-local
		{"169.254.1.1", true, "IPv4 link-local"},
		{"fe80::1", true, "IPv6 link-local"},
		// Unspecified
		{"0.0.0.0", true, "IPv4 unspecified"},
		{"::", true, "IPv6 unspecified"},
		// 0.0.0.0/8
		{"0.1.2.3", true, "0.0.0.0/8 non-zero host"},
		// Multicast
		{"224.0.0.1", true, "IPv4 multicast"},
		{"ff02::1", true, "IPv6 multicast"},
		// CGNAT 100.64.0.0/10
		{"100.64.0.1", true, "CGNAT low boundary"},
		{"100.100.0.1", true, "CGNAT mid"},
		{"100.127.255.255", true, "CGNAT high boundary"},
		// CGNAT boundaries that must NOT be blocked
		{"100.63.255.255", false, "just below CGNAT"},
		{"100.128.0.1", false, "just above CGNAT"},
		// IPv4-mapped IPv6 — must unmap then apply the v4 rules (bypass guard)
		{"::ffff:127.0.0.1", true, "mapped loopback"},
		{"::ffff:10.0.0.1", true, "mapped RFC1918"},
		{"::ffff:8.8.8.8", false, "mapped public must stay allowed"},
		// Public — must be reachable
		{"8.8.8.8", false, "public v4"},
		{"1.1.1.1", false, "public v4"},
		{"93.184.216.34", false, "public v4"},
		{"2606:4700:4700::1111", false, "public v6"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("%s: unparseable test IP %q", c.why, c.ip)
		}
		if got := IsBlockedIP(ip); got != c.blocked {
			t.Errorf("IsBlockedIP(%s) = %v, want %v (%s)", c.ip, got, c.blocked, c.why)
		}
	}
}

func TestIsValidCIDR(t *testing.T) {
	valid := []string{"10.0.0.0/8", "192.168.1.0/24", "8.8.8.8", "::1", "2606:4700::/32"}
	invalid := []string{"", "not-an-ip", "10.0.0.0/33", "999.0.0.1", "10.0.0.0/-1"}
	for _, s := range valid {
		if !IsValidCIDR(s) {
			t.Errorf("IsValidCIDR(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if IsValidCIDR(s) {
			t.Errorf("IsValidCIDR(%q) = true, want false", s)
		}
	}
}

// IsLANBogonCIDR gates what may enter a SOURCE blacklist — a private CIDR there
// would lock out LAN clients, so it must flag private/bogon ranges (IP or CIDR).
func TestIsLANBogonCIDR(t *testing.T) {
	cases := []struct {
		s     string
		bogon bool
	}{
		{"10.0.0.0/8", true},
		{"192.168.0.0/16", true},
		{"127.0.0.1", true},
		{"169.254.0.0/16", true},
		{"100.64.0.0/10", true},
		{"8.8.8.8", false},
		{"93.184.216.0/24", false},
		{"garbage", false}, // unparseable → not a bogon (caller validates separately)
	}
	for _, c := range cases {
		if got := IsLANBogonCIDR(c.s); got != c.bogon {
			t.Errorf("IsLANBogonCIDR(%q) = %v, want %v", c.s, got, c.bogon)
		}
	}
}

// IsSSRFTarget is exercised with IP-literal URLs so it stays deterministic and
// offline (net.LookupHost on a literal returns the literal without a real DNS
// query). Hostname resolution paths are covered by integration tests.
func TestIsSSRFTarget(t *testing.T) {
	cases := []struct {
		url     string
		ssrf    bool
		wantErr bool
	}{
		{"http://127.0.0.1/", true, false},      // loopback literal
		{"https://10.0.0.5/admin", true, false}, // RFC1918 literal
		{"http://[::1]:8080/", true, false},     // IPv6 loopback literal
		{"http://8.8.8.8/", false, false},       // public literal
		{"https://1.1.1.1/dns", false, false},   // public literal
		{"ftp://8.8.8.8/", true, true},          // non-http scheme rejected
		{"http:///path", true, true},            // empty hostname
		{"://bad", true, true},                  // unparseable
	}
	for _, c := range cases {
		got, err := IsSSRFTarget(c.url)
		if (err != nil) != c.wantErr {
			t.Errorf("IsSSRFTarget(%q) err = %v, wantErr %v", c.url, err, c.wantErr)
		}
		if got != c.ssrf {
			t.Errorf("IsSSRFTarget(%q) = %v, want %v", c.url, got, c.ssrf)
		}
	}
}
