package auth

import "testing"

func TestTokenAllows(t *testing.T) {
	for _, c := range []struct {
		scope, method, route string
		want                 bool
	}{
		{"read", "GET", "/api/settings", true},
		{"read", "HEAD", "/api/logs", true},
		{"read", "POST", "/api/settings", false},
		{"read", "DELETE", "/api/ip-blacklist/{id}", false},
		{"write", "POST", "/api/settings", true},
		{"write", "DELETE", "/api/ip-blacklist/{id}", true},
		{"write", "GET", "/api/tokens", false},
		{"write", "DELETE", "/api/tokens/{id}", false},
		{"write", "POST", "/api/change-password", false},
		{"write", "POST", "/api/logout", false},
		{"write", "POST", "/api/auth/refresh", false},
		{"read", "GET", "/api/database/export", false},
		{"write", "POST", "/api/database/reset", false},
		{"read", "GET", "/api/maintenance/backup-config", false},
		{"write", "POST", "/api/maintenance/restore-config", false},
		{"write", "POST", "/api/internal/alert", false},
		{"read", "GET", "/debug/pprof/*", false},
		// A route that only starts like a refused one is not refused.
		{"read", "GET", "/api/tokensx", true},
		{"read", "GET", "/api/database/size", true},
		{"read", "GET", "", false},
		{"admin", "GET", "/api/settings", false},
		{"", "GET", "/api/settings", false},
	} {
		if got := TokenAllows(c.scope, c.method, c.route); got != c.want {
			t.Errorf("TokenAllows(%q, %q, %q) = %v, want %v", c.scope, c.method, c.route, got, c.want)
		}
	}
}
