package engine

import "testing"

func TestIsReservedName(t *testing.T) {
	for _, c := range []struct {
		host string
		want bool
	}{
		{"this-url-does-not-exist-0f3c.invalid", true},
		{"X.INVALID:443", true},
		{"x.invalid.", true},
		{"a.b.test", true},
		{"www.example", true},
		{"localhost", true},
		{"api.localhost:8080", true},
		{"example.com", false},
		{"x.invalid.com", false},
		{"invalidx", false},
		{"test.com:443", false},
		{"paypa1.com", false},
		{"[::1]:443", false},
		{"", false},
	} {
		if got := IsReservedName(c.host); got != c.want {
			t.Errorf("IsReservedName(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}
