package main

import (
	"testing"
)

func TestCheckTyposquat(t *testing.T) {
	tests := []struct {
		domain    string
		suspicious bool
	}{
		{"google.com", false},
		{"github.com", false},
		{"g00gle.com", true},
		{"goolge.com", true},
		{"rnicrosoft.com", true},
		{"paypa1.com", true},
		{"appl.ecom", true},
		{"apple.com", false},
		// Regression: legitimate domains that the TLD-blind detector wrongly
		// flagged. github.io/gitlab.io are public suffixes; yahoo.co is the same
		// brand on another TLD; chess.com is unrelated to chase.com (2 edits, no
		// swap).
		{"user.github.io", false},
		{"myapp.gitlab.io", false},
		{"github.io", false},
		{"yahoo.co", false},
		{"chess.com", false},
		{"g1thub.com", true},
	}

	for _, tt := range tests {
		res := CheckTyposquat(tt.domain)
		if res.Suspicious != tt.suspicious {
			t.Errorf("CheckTyposquat(%q) = %v, want %v", tt.domain, res.Suspicious, tt.suspicious)
		}
	}
}

func TestReplaceHomoglyphs(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"g00gle", "google"},
		{"paya1", "payal"},
		{"rnicrosoft", "microsoft"},
		{"vva", "wa"}, // wait, vv -> w
		{"safe", "safe"},
	}

	for _, tt := range tests {
		if got := replaceHomoglyphs(tt.input); got != tt.want {
			t.Errorf("replaceHomoglyphs(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
