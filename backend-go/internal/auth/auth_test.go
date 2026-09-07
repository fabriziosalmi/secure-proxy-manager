package auth

import (
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// RevokeJWTOnce must let exactly one caller consume a given token even under
// concurrent access — this is the gate that prevents refresh-token replay.
func TestRevokeJWTOnceIsSingleUse(t *testing.T) {
	cfg := &config.Config{
		SecretKey:         "super-secret-key-for-testing-1234567",
		JWTExpireDuration: 1 * time.Hour,
	}
	s := NewService(cfg, nil)
	token, err := s.IssueRefreshToken("alice")
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	var winners int64
	var mu sync.Mutex
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if s.RevokeJWTOnce(token) {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("expected exactly 1 caller to consume the token, got %d", winners)
	}
}

func TestHashPassword(t *testing.T) {
	password := "mypassword"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if len(hash) == 0 {
		t.Fatal("Empty hash returned")
	}
}

func TestJWTFlow(t *testing.T) {
	cfg := &config.Config{
		SecretKey:         "super-secret-key-for-testing-1234567",
		JWTExpireDuration: 1 * time.Hour,
	}
	s := NewService(cfg, nil)

	username := "testuser"
	token, err := s.IssueJWT(username)
	if err != nil {
		t.Fatalf("IssueJWT failed: %v", err)
	}

	gotUsername, err := s.ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}
	if gotUsername != username {
		t.Errorf("Expected %s, got %s", username, gotUsername)
	}

	// Revoke
	s.RevokeJWT(token)
	_, err = s.ValidateJWT(token)
	if err == nil {
		t.Error("Expected error for revoked token")
	}
}

// Refresh tokens must NOT be accepted by ValidateJWT — that path is only for
// access tokens. Otherwise a 7-day refresh token can authenticate every API
// call for a week instead of the short-lived access window.
func TestValidateJWTRejectsRefreshToken(t *testing.T) {
	cfg := &config.Config{
		SecretKey:         "super-secret-key-for-testing-1234567",
		JWTExpireDuration: 1 * time.Hour,
	}
	s := NewService(cfg, nil)

	refresh, err := s.IssueRefreshToken("alice")
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	if _, err := s.ValidateJWT(refresh); err == nil {
		t.Fatal("ValidateJWT accepted a refresh token — refresh tokens must be rejected on the access path")
	}

	// Sanity: refresh path still works.
	if _, err := s.ValidateRefreshToken(refresh); err != nil {
		t.Fatalf("ValidateRefreshToken on a refresh token failed: %v", err)
	}

	// Reverse: an access token must NOT be accepted on the refresh path.
	access, err := s.IssueJWT("alice")
	if err != nil {
		t.Fatalf("IssueJWT failed: %v", err)
	}
	if _, err := s.ValidateRefreshToken(access); err == nil {
		t.Fatal("ValidateRefreshToken accepted an access token")
	}
}

func TestAuthenticateBasic(t *testing.T) {
	cfg := &config.Config{
		AdminUsername:   "admin",
		AdminPassword:   "password",
		MaxAttempts:     5,
		RateLimitWindow: 1 * time.Minute,
	}
	s := NewService(cfg, nil)

	// Correct
	r := httptest.NewRequest("GET", "/", nil)
	r.SetBasicAuth("admin", "password")
	r.RemoteAddr = "1.2.3.4:1234"
	username, isBasic, err := s.Authenticate(r)
	if err != nil {
		t.Errorf("Authenticate failed: %v", err)
	}
	if username != "admin" || !isBasic {
		t.Errorf("Unexpected result: %s, %v", username, isBasic)
	}

	// Incorrect
	r = httptest.NewRequest("GET", "/", nil)
	r.SetBasicAuth("admin", "wrong")
	_, _, err = s.Authenticate(r)
	if err == nil {
		t.Error("Expected error for wrong password")
	}
}

func TestRateLimit(t *testing.T) {
	cfg := &config.Config{
		AdminUsername:   "admin",
		AdminPassword:   "password",
		MaxAttempts:     2,
		RateLimitWindow: 1 * time.Minute,
	}
	s := NewService(cfg, nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.1.1.1:1234"
	r.SetBasicAuth("admin", "wrong")

	// 1st fail
	_, _, _ = s.Authenticate(r)
	// 2nd fail
	_, _, _ = s.Authenticate(r)

	// 3rd attempt should be blocked
	_, _, err := s.Authenticate(r)
	if err == nil || err.Error() != "too many failed attempts, try again later" {
		t.Errorf("Expected rate limit error, got %v", err)
	}

	// Clear rate limit
	if !s.ClearRateLimit("1.1.1.1") {
		t.Error("ClearRateLimit failed")
	}
	_, _, err = s.Authenticate(r)
	if err != nil && err.Error() == "too many failed attempts, try again later" {
		t.Error("Rate limit still active after clearing")
	}
}

func TestWSTokens(t *testing.T) {
	cfg := &config.Config{}
	s := NewService(cfg, nil)

	token := s.IssueWSToken("user1")
	user, ok := s.ValidateWSToken(token)
	if !ok || user != "user1" {
		t.Errorf("WSToken validation failed")
	}

	// Should be consumed
	_, ok = s.ValidateWSToken(token)
	if ok {
		t.Error("Token should have been consumed")
	}
}

func TestTrustedProxy(t *testing.T) {
	if !trustedProxy("127.0.0.1:1234") {
		t.Error("127.0.0.1 should be trusted")
	}
	if trustedProxy("8.8.8.8:1234") {
		t.Error("8.8.8.8 should not be trusted")
	}
}

// SECURE-ERR-02: an unreadable revocation store must not be read as "nothing is
// revoked". A token that predates this process cannot be checked against the
// blacklist, so it must be refused rather than trusted.
func TestValidateJWTFailsClosedWhenBlacklistUnavailable(t *testing.T) {
	cfg := &config.Config{
		SecretKey:         "super-secret-key-for-testing-1234567",
		JWTExpireDuration: 1 * time.Hour,
	}
	svc := NewService(cfg, nil)

	tok, err := svc.IssueJWT("admin")
	if err != nil {
		t.Fatalf("IssueJWT: %v", err)
	}
	if _, err := svc.ValidateJWT(tok); err != nil {
		t.Fatalf("token issued after startup must validate: %v", err)
	}

	// Simulate the store being unavailable at boot.
	svc.blacklistUnavailable.Store(true)

	// A token issued after this process started is still known to it.
	if _, err := svc.ValidateJWT(tok); err != nil {
		t.Errorf("post-start token should still validate, got %v", err)
	}

	// A token that predates startup cannot be checked and must be refused.
	old := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  "admin",
		"type": "access",
		"iat":  startedAt.Add(-time.Hour).Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	oldStr, err := old.SignedString([]byte(cfg.SecretKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := svc.ValidateJWT(oldStr); err == nil {
		t.Error("pre-start token was accepted while the revocation store was unavailable — fail-open")
	}
}

// SECURE-ERR-03: a revocation that cannot be persisted must be reported, not
// swallowed, so the caller does not promise a logout it cannot keep.
func TestRevokeJWTReportsPersistFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	svc := NewService(&config.Config{
		SecretKey:         "super-secret-key-for-testing-1234567",
		JWTExpireDuration: 1 * time.Hour,
	}, db)

	tok, err2 := svc.IssueJWT("admin")
	if err2 != nil {
		t.Fatalf("IssueJWT: %v", err2)
	}
	if err := svc.RevokeJWT(tok); err != nil {
		t.Fatalf("healthy revoke should succeed: %v", err)
	}

	// Drop the table out from under it: the write now fails.
	if _, err := db.Exec("DROP TABLE jwt_blacklist"); err != nil {
		t.Fatalf("drop: %v", err)
	}
	tok2, _ := svc.IssueJWT("admin")
	if err := svc.RevokeJWT(tok2); err == nil {
		t.Error("RevokeJWT returned nil when the revocation could not be persisted")
	}
}

// SECURE-ERR-02 (refresh path): the same fail-closed guard must apply to
// refresh tokens, which are long-lived and therefore the more valuable replay.
func TestValidateRefreshTokenFailsClosedWhenBlacklistUnavailable(t *testing.T) {
	cfg := &config.Config{
		SecretKey:         "super-secret-key-for-testing-1234567",
		JWTExpireDuration: 1 * time.Hour,
	}
	svc := NewService(cfg, nil)
	svc.blacklistUnavailable.Store(true)

	old := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  "admin",
		"type": "refresh",
		"iat":  startedAt.Add(-time.Hour).Unix(),
		"exp":  time.Now().Add(24 * time.Hour).Unix(),
	})
	oldStr, err := old.SignedString([]byte(cfg.SecretKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := svc.ValidateRefreshToken(oldStr); err == nil {
		t.Error("pre-start refresh token was accepted while the revocation store was unavailable — fail-open")
	}
}
