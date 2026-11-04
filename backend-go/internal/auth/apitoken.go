package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// ViaToken is a request authenticated by an API token (database.APIToken).
const ViaToken = "token"

// TokenUserPrefix starts the username a token request acts as, so the audit
// log names the token: "token:<name>".
const TokenUserPrefix = "token:"

// Principal is who a request authenticated as: the username, where the
// credential came from, and the API token when it was one.
type Principal struct {
	Username string
	Via      string
	Token    *database.APIToken
}

var errInvalidToken = errors.New("invalid API token")

// isAPIToken reports whether an Authorization header carries an API token
// rather than a JWT.
func isAPIToken(authHeader string) (string, bool) {
	value, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok || !strings.HasPrefix(value, database.APITokenPrefix) {
		return "", false
	}
	return value, true
}

// authenticateToken checks an API token. A failure counts against the
// client like a wrong password, so tokens cannot be guessed faster than
// passwords; a success refunds the attempt and records the use.
func (s *Service) authenticateToken(r *http.Request, value string) (Principal, error) {
	if s.db == nil {
		return Principal{}, errInvalidToken
	}
	refund, err := s.reserveAttempt(r)
	if err != nil {
		return Principal{}, err
	}
	now := time.Now()
	t, ok, err := database.CheckAPIToken(s.db, value, now)
	if err != nil {
		log.Error().Err(err).Msg("cannot read API tokens; refusing the request")
		refund() // the store failed, the client did not guess wrong
		return Principal{}, errors.New("token store unavailable")
	}
	if !ok {
		return Principal{}, errInvalidToken
	}
	refund()
	database.TouchAPIToken(s.db, t.ID, now)
	return Principal{Username: TokenUserPrefix + t.Name, Via: ViaToken, Token: &t}, nil
}

// tokenDenied are the routes no API token reaches, whatever its scope: the
// token routes themselves (a token cannot mint or revoke tokens), the admin
// password and session routes, the database export and reset, the
// configuration backup and restore, the service routes and the runtime
// profiles. A route matches when it is one of these or lies under one.
var tokenDenied = []string{
	"/api/tokens",
	"/api/change-password",
	"/api/logout",
	"/api/auth",
	"/api/database/export",
	"/api/database/reset",
	"/api/maintenance/backup-config",
	"/api/maintenance/restore-config",
	"/api/internal",
	"/debug",
}

// TokenAllows reports whether a token of scope may call method on route,
// the router's pattern for the request (for example /api/ip-blacklist/{id}),
// not the path the client sent, so no spelling of a path slips past it. A
// read token may GET and HEAD; a write token may call any method; neither
// reaches tokenDenied. An empty route or an unknown scope is refused.
func TokenAllows(scope, method, route string) bool {
	if route == "" {
		return false
	}
	for _, d := range tokenDenied {
		if route == d || strings.HasPrefix(route, d+"/") {
			return false
		}
	}
	switch scope {
	case database.ScopeRead:
		return method == http.MethodGet || method == http.MethodHead
	case database.ScopeWrite:
		return true
	}
	return false
}
