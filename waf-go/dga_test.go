package main

import (
	"testing"
)

func TestAnalyzeDGA(t *testing.T) {
	tests := []struct {
		domain  string
		wantDGA bool
	}{
		{"google.com", false},
		{"github.com", false},
		{"xkqzqfblweabcxyzqrstuvwxzzzz1234567890.com", true},
		{"example.com", false},
		{"1234567890abcdefghij1234567890qwertyuiop.biz", true},
		{"a.com", false},
		{"b.com", false},
	}

	for _, tt := range tests {
		res := AnalyzeDGA(tt.domain)
		if res.IsDGA != tt.wantDGA {
			t.Errorf("AnalyzeDGA(%q) = %v, want %v (score: %d)", tt.domain, res.IsDGA, tt.wantDGA, res.Score)
		}
	}
}
