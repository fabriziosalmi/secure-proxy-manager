package main

import (
	"testing"
)

func TestIsLANHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"::1", true},
		{"[::1]:8080", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"0.0.0.0", true},
		{"google.com", false},
		{"8.8.8.8", false},
		{"172.32.0.1", false},
		// regression: previously bypassed via "172.2" prefix match
		{"172.200.0.1", false},
		{"172.255.255.255", false},
		{"2.2.2.2", false},
		{"100.64.0.1", false}, // CGNAT, not RFC1918 — must be inspected
		{"evil.example.com:172", false},
	}

	for _, tt := range tests {
		if got := isLANHost(tt.host); got != tt.want {
			t.Errorf("isLANHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestIsTextContent(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"text/html", true},
		{"TEXT/pLaIn", true},
		{"application/xml", true},
		{"image/png", false},
		{"application/octet-stream", false},
	}

	for _, tt := range tests {
		if got := isTextContent(tt.ct); got != tt.want {
			t.Errorf("isTextContent(%q) = %v, want %v", tt.ct, got, tt.want)
		}
	}
}
