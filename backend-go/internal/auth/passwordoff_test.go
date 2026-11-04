package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

func TestPasswordOffNeedsTheProviderAndTheDashboard(t *testing.T) {
	dashboard := httptest.NewRequest("GET", "/api/settings", nil)
	dashboard.Header.Set("X-Forwarded-For", "198.51.100.7")
	direct := httptest.NewRequest("GET", "/api/settings", nil)
	direct.Header.Set("X-Forwarded-For", "") // as Login's copy of a direct request carries it

	for _, c := range []struct {
		name string
		oidc config.OIDC
		want bool
	}{
		{"off, through the dashboard", config.OIDC{Issuer: "https://id.example.com", PasswordOff: true}, true},
		{"left on", config.OIDC{Issuer: "https://id.example.com"}, false},
		// Never without a provider: nobody could sign in to the dashboard.
		{"no provider", config.OIDC{PasswordOff: true}, false},
	} {
		s := &Service{cfg: &config.Config{OIDC: c.oidc}}
		if got := s.PasswordOff(dashboard); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if s.PasswordOff(direct) {
			t.Errorf("%s: refused on the backend port", c.name)
		}
	}
}
