package handlers

import (
	"testing"
)

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
