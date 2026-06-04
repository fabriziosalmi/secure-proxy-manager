package handlers

import (
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.169.254",                          // cloud metadata
		"0.0.0.0", "100.64.0.1", "100.127.255.255", // CGNAT
		"224.0.0.1", "fe80::1", "fc00::1",
	}
	for _, s := range blocked {
		if ip := net.ParseIP(s); ip == nil || !isBlockedIP(ip) {
			t.Errorf("isBlockedIP(%q) = false, want true", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "100.63.255.255", "100.128.0.1", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if ip := net.ParseIP(s); ip == nil || isBlockedIP(ip) {
			t.Errorf("isBlockedIP(%q) = true, want false", s)
		}
	}
}

func TestIsLANBogonCIDR(t *testing.T) {
	bogon := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
		"192.168.122.0/24", "10.1.2.3", "127.0.0.1", "::1", "fe80::/10", "fc00::/7",
	}
	for _, c := range bogon {
		if !isLANBogonCIDR(c) {
			t.Errorf("isLANBogonCIDR(%q) = false, want true", c)
		}
	}
	routable := []string{"8.8.8.8/32", "1.1.1.1", "93.184.216.0/24", "203.0.113.5", "2606:4700::/32"}
	for _, c := range routable {
		if isLANBogonCIDR(c) {
			t.Errorf("isLANBogonCIDR(%q) = true, want false", c)
		}
	}
}

func TestIsWritableSettingKey(t *testing.T) {
	bad := []string{"default_password_changed", "has space", "semi;colon", "", "../etc"}
	for _, k := range bad {
		if isWritableSettingKey(k) {
			t.Errorf("isWritableSettingKey(%q) = true, want false", k)
		}
	}
	good := []string{"enable_waf", "webhook_url", "proxy_port", "enable_safesearch"}
	for _, k := range good {
		if !isWritableSettingKey(k) {
			t.Errorf("isWritableSettingKey(%q) = false, want true", k)
		}
	}
}

func TestHelpers_IsValidCIDR(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"1.1.1.1", true},
		{"192.168.1.0/24", true},
		{"invalid", false},
		{"256.256.256.256", false},
		{"::1", true},
	}
	for _, c := range cases {
		if got := isValidCIDR(c.input); got != c.want {
			t.Errorf("isValidCIDR(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestHelpers_IsSSRFTarget(t *testing.T) {
	// Note: this involves DNS lookups, so we test localhost/private
	cases := []struct {
		input string
		want  bool
	}{
		{"http://localhost", true},
		{"http://127.0.0.1", true},
		{"http://169.254.169.254", true},
		{"http://google.com", false},
		{"ftp://example.com", true}, // only http/https allowed
	}
	for _, c := range cases {
		got, _ := isSSRFTarget(c.input)
		if got != c.want {
			t.Errorf("isSSRFTarget(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestHelpers_ExtractDomain(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"http://example.com/path", "example.com"},
		{"https://sub.example.com:8080/path", "sub.example.com"},
		{"example.com", "example.com"},
	}
	for _, c := range cases {
		if got := extractDomain(c.input); got != c.want {
			t.Errorf("extractDomain(%q) = %s, want %s", c.input, got, c.want)
		}
	}
}

func TestHelpers_MaskIP(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"192.168.1.7", "192.168.1.x"},
		{"::1", "::x"},
		{"invalid", "invalid"},
	}
	for _, c := range cases {
		if got := maskIP(c.input); got != c.want {
			t.Errorf("maskIP(%q) = %s, want %s", c.input, got, c.want)
		}
	}
}
