package auth

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

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
