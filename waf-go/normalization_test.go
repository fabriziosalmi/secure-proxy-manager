package main

import (
	"strings"
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

func TestPercentDecodeTolerant(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"%41%42%43", "ABC"},
		{"a+b", "a b"},
		{"nothing-here", "nothing-here"},
		{"%2e%2e%2f", "../"},
		// A single malformed escape must NOT abort decoding of the rest.
		{"%3Cscript%3E%ZZ", "<script>%ZZ"},
		{"%ZZ", "%ZZ"},
		{"trailing%", "trailing%"},
		{"half%4", "half%4"},
	}
	for _, tt := range tests {
		if got := percentDecodeTolerant(tt.in); got != tt.want {
			t.Errorf("percentDecodeTolerant(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestNormalizeDefeatsInvalidEscapeBypass guards the regression where a single
// invalid percent-token disabled all decoding, letting an encoded payload slip
// through unscanned.
func TestNormalizeDefeatsInvalidEscapeBypass(t *testing.T) {
	got := normalizeInput("/?x=%3Cscript%3Ealert(1)%3C/script%3E%ZZ")
	if !strings.Contains(got, "<script>") {
		t.Fatalf("expected decoded <script> in %q — invalid-escape bypass not closed", got)
	}
	if _, score := matchRulesScored(got); score == 0 {
		t.Errorf("expected the decoded payload to score > 0, got 0 (input still evades rules)")
	}
}

func TestShouldInspectBody(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"application/octet-stream", true}, // must NOT be skippable
		{"", true},
		{"application/json", true},
		{"text/html", true},
		{"application/zip", true},
		{"image/png", false},
		{"video/mp4", false},
		{"font/woff2", false},
		{"AUDIO/mpeg", false},
	}
	for _, tt := range tests {
		if got := shouldInspectBody(tt.ct); got != tt.want {
			t.Errorf("shouldInspectBody(%q) = %v, want %v", tt.ct, got, tt.want)
		}
	}
}
