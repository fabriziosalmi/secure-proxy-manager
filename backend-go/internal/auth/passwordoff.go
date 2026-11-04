package auth

import (
	"errors"
	"net/http"
	"strings"
)

// ErrPasswordOff turns the local admin away from the dashboard while
// OIDC_PASSWORD_LOGIN=false.
var ErrPasswordOff = errors.New("password sign-in is turned off on the dashboard: sign in with the provider, or use the backend's own port")

// viaDashboard reports whether r came through the dashboard's nginx. nginx
// sets X-Forwarded-For and X-Real-IP on every request it passes to /api/,
// replacing what the client sent (ui/nginx.conf.template), so a client of the
// dashboard cannot arrive without them. A request on the backend's own port
// has neither unless its sender adds one, which turns only that sender away.
func viaDashboard(r *http.Request) bool {
	return r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != ""
}

// PasswordOff reports whether the local admin's password is refused on r:
// OIDC is on, OIDC_PASSWORD_LOGIN=false, and r came through the dashboard.
// The backend's own port (127.0.0.1 only in the compose files) stays open to
// it, as break-glass.
func (s *Service) PasswordOff(r *http.Request) bool {
	return s.cfg.OIDC.Enabled() && s.cfg.OIDC.PasswordOff && viaDashboard(r)
}

// AdminAllowed returns ErrPasswordOff when username is the local admin and
// PasswordOff(r): a session signed in with the password on the backend's port
// is not taken to the dashboard either. OIDC sessions and API tokens are
// never turned away here.
func (s *Service) AdminAllowed(r *http.Request, username string) error {
	if strings.HasPrefix(username, OIDCUserPrefix) || strings.HasPrefix(username, TokenUserPrefix) {
		return nil
	}
	if s.PasswordOff(r) {
		return ErrPasswordOff
	}
	return nil
}
