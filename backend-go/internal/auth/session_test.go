package auth

import (
	"encoding/base64"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

func sessionTestService(t *testing.T) *Service {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	hash, _ := HashPassword("Old-passw0rd!")
	if err := database.Init(db, "admin", hash); err != nil {
		t.Fatalf("init db: %v", err)
	}
	return NewService(&config.Config{
		SecretKey:         "super-secret-key-for-testing-1234567",
		JWTExpireDuration: time.Hour,
		AdminUsername:     "admin",
		MaxAttempts:       5,
		RateLimitWindow:   5 * time.Minute,
	}, db)
}

func setPassword(t *testing.T, s *Service, plaintext string) {
	t.Helper()
	hash, _ := HashPassword(plaintext)
	if _, err := s.db.Exec("UPDATE users SET password = ? WHERE username = 'admin'", hash); err != nil {
		t.Fatalf("set password: %v", err)
	}
}

// Rotating the password is how an operator evicts someone holding a stolen
// token. It used to revoke nothing: the old access token stayed valid for its
// 8 hours and the old refresh token kept minting fresh pairs indefinitely.
func TestPasswordChangeInvalidatesExistingSessions(t *testing.T) {
	s := sessionTestService(t)
	access, _ := s.IssueJWT("admin")
	refresh, _ := s.IssueRefreshToken("admin")
	if _, err := s.ValidateJWT(access); err != nil {
		t.Fatalf("fresh access token refused: %v", err)
	}

	setPassword(t, s, "New-passw0rd!")

	if _, err := s.ValidateJWT(access); err == nil {
		t.Error("an access token issued before the password change is still accepted")
	}
	if _, err := s.ValidateRefreshToken(refresh); err == nil {
		t.Error("a refresh token issued before the password change is still accepted")
	}
	fresh, _ := s.IssueJWT("admin")
	if _, err := s.ValidateJWT(fresh); err != nil {
		t.Errorf("a token issued after the change is refused: %v", err)
	}
}

// Without a unique claim two tokens issued in the same second were the same
// string, so revoking one (logout in one browser) revoked the other.
func TestTokensIssuedInTheSameSecondAreDistinct(t *testing.T) {
	s := sessionTestService(t)
	a, _ := s.IssueJWT("admin")
	b, _ := s.IssueJWT("admin")
	if a == b {
		t.Fatal("two access tokens issued back to back are identical")
	}
	if err := s.RevokeJWT(a); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.ValidateJWT(b); err != nil {
		t.Errorf("revoking one session revoked another: %v", err)
	}
	r1, _ := s.IssueRefreshToken("admin")
	r2, _ := s.IssueRefreshToken("admin")
	if r1 == r2 {
		t.Error("two refresh tokens issued back to back are identical")
	}
}

// Each refresh issued a new 7-day token, so a chain of refreshes never ended.
// The chain is now bounded by the time of the login it descends from.
func TestRefreshChainEndsAWeekAfterLogin(t *testing.T) {
	s := sessionTestService(t)
	login := time.Now().Add(-maxSessionLifetime - time.Minute)
	tok, err := s.IssueRefreshTokenAt("admin", login)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, _, err := s.ValidateRefreshSession(tok); err == nil {
		t.Error("a refresh token descending from a login over a week ago is still accepted")
	}

	recent := time.Now().Add(-time.Hour)
	tok, _ = s.IssueRefreshTokenAt("admin", recent)
	user, authTime, err := s.ValidateRefreshSession(tok)
	if err != nil || user != "admin" {
		t.Fatalf("recent session refused: %v", err)
	}
	if authTime.Unix() != recent.Unix() {
		t.Errorf("auth_time not carried: got %v, want %v", authTime, recent)
	}
	parsed, _, _ := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	exp, _ := parsed.Claims.(jwt.MapClaims).GetExpirationTime()
	if exp == nil || exp.After(recent.Add(maxSessionLifetime).Add(time.Second)) {
		t.Errorf("refresh token outlives its session: exp %v, session ends %v", exp, recent.Add(maxSessionLifetime))
	}
}

// A token minted before this change carries no password binding; it must be
// refused rather than treated as bound to the current password.
func TestTokenWithoutPasswordBindingIsRefused(t *testing.T) {
	s := sessionTestService(t)
	legacy := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "admin", "type": "access",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	str, _ := legacy.SignedString([]byte(s.cfg.SecretKey))
	if _, err := s.ValidateJWT(str); err == nil {
		t.Error("a token without the password binding was accepted")
	}
}

// The failure was recorded only after bcrypt finished, so every request in
// flight had already passed the limit check: 40 concurrent guesses against a
// limit of 5 were all evaluated.
func TestConcurrentFailedLoginsRespectTheLimit(t *testing.T) {
	s := sessionTestService(t)
	var evaluated, limited atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "203.0.113.9:4000"
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:wrong-guess")))
			_, _, err := s.Authenticate(r)
			switch {
			case err == nil:
				t.Error("a wrong password was accepted")
			case err.Error() == "too many failed attempts, try again later":
				limited.Add(1)
			default:
				evaluated.Add(1)
			}
		}()
	}
	wg.Wait()
	if evaluated.Load() > int32(s.cfg.MaxAttempts) {
		t.Errorf("%d guesses were evaluated against a limit of %d", evaluated.Load(), s.cfg.MaxAttempts)
	}
	if limited.Load() == 0 {
		t.Error("no request was rate limited")
	}
}

// A successful login must not consume an attempt, or a user who logs in
// correctly five times in a row locks themselves out.
func TestSuccessfulLoginsDoNotConsumeAttempts(t *testing.T) {
	s := sessionTestService(t)
	for i := 0; i < 8; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "203.0.113.10:4000"
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:Old-passw0rd!")))
		if _, _, err := s.Authenticate(r); err != nil {
			t.Fatalf("login %d refused: %v", i+1, err)
		}
	}
}
