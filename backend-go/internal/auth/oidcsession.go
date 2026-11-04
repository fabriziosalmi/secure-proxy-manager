package auth

import (
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCUserPrefix starts the username of a person signed in with the OIDC
// provider: "oidc:<email>", as the audit log records it. The local admin's
// name never has it, so the two kinds of session cannot be mistaken.
const OIDCUserPrefix = "oidc:"

// IssueOIDCSession signs a dashboard session for a person the OIDC provider
// signed in. It lasts cfg.OIDC.Session and is not refreshed. In place of the
// password binding (pv) it carries the OIDC configuration's fingerprint (ob),
// so changing the provider or who may sign in ends it.
func (s *Service) IssueOIDCSession(email string) (string, time.Time, error) {
	if !s.cfg.OIDC.Enabled() {
		return "", time.Time{}, errors.New("OIDC sign-in is not configured")
	}
	now := time.Now()
	exp := now.Add(s.cfg.OIDC.Session)
	claims := jwt.MapClaims{
		"sub":  OIDCUserPrefix + email,
		"exp":  exp.Unix(),
		"iat":  now.Unix(),
		"jti":  tokenID(),
		"ob":   s.cfg.OIDC.Fingerprint(),
		"idp":  "oidc",
		"type": "access",
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.cfg.SecretKey))
	return token, time.Unix(exp.Unix(), 0), err
}

// checkOIDCBinding is checkPasswordBinding for an OIDC session: OIDC is
// configured as it was when the session was issued. The fingerprint includes
// the issuer, so switching OIDC off ends the session too.
func (s *Service) checkOIDCBinding(claims jwt.MapClaims) error {
	if idp, _ := claims["idp"].(string); idp != "oidc" {
		return errors.New("not an OIDC session")
	}
	ob, _ := claims["ob"].(string)
	if subtle.ConstantTimeCompare([]byte(ob), []byte(s.cfg.OIDC.Fingerprint())) != 1 {
		return errors.New("the OIDC configuration changed since this sign-in; sign in again")
	}
	return nil
}

// sessionBinding checks the binding a session's subject calls for.
func (s *Service) sessionBinding(claims jwt.MapClaims, username string) error {
	if strings.HasPrefix(username, OIDCUserPrefix) {
		return s.checkOIDCBinding(claims)
	}
	return s.checkPasswordBinding(claims, username)
}
