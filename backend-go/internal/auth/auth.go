// Package auth provides JWT issuance/validation, bcrypt password hashing,
// per-IP rate limiting, and one-time WebSocket tokens.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

// Service handles all authentication concerns.
type Service struct {
	cfg *config.Config

	jwtBlacklistMu sync.RWMutex
	jwtBlacklist   map[string]time.Time

	attemptsMu sync.Mutex
	attempts   map[string][]time.Time

	wsTokenMu sync.Mutex
	wsTokens  map[string]wsEntry
}

type wsEntry struct {
	username string
	expiry   time.Time
}

// NewService creates a ready-to-use auth Service.
func NewService(cfg *config.Config) *Service {
	svc := &Service{
		cfg:          cfg,
		jwtBlacklist: make(map[string]time.Time),
		attempts:     make(map[string][]time.Time),
		wsTokens:     make(map[string]wsEntry),
	}
	go svc.cleanupLoop()
	return svc
}

// HashPassword produces a bcrypt hash of plaintext.
func HashPassword(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	return string(hash), err
}

// IssueJWT signs and returns a JWT for the given username.
func (s *Service) IssueJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"sub": username,
		"exp": time.Now().Add(s.cfg.JWTExpireDuration).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.SecretKey))
}

// ValidateJWT parses and validates a signed JWT string.
func (s *Service) ValidateJWT(tokenStr string) (string, error) {
	s.jwtBlacklistMu.RLock()
	if expiry, revoked := s.jwtBlacklist[tokenStr]; revoked && time.Now().Before(expiry) {
		s.jwtBlacklistMu.RUnlock()
		return "", errors.New("token has been revoked")
	}
	s.jwtBlacklistMu.RUnlock()

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.cfg.SecretKey), nil
	})
	if err != nil || !token.Valid {
		return "", errors.New("invalid or expired token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}
	username, _ := claims["sub"].(string)
	if username == "" {
		return "", errors.New("missing subject")
	}
	return username, nil
}

// RevokeJWT adds a token to the blacklist.
func (s *Service) RevokeJWT(tokenStr string) {
	parser := jwt.NewParser()
	token, _, _ := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	exp := time.Now().Add(s.cfg.JWTExpireDuration)
	if token != nil {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if expClaim, err := claims.GetExpirationTime(); err == nil && expClaim != nil {
				exp = expClaim.Time
			}
		}
	}
	s.jwtBlacklistMu.Lock()
	s.jwtBlacklist[tokenStr] = exp
	s.jwtBlacklistMu.Unlock()
}

// Authenticate extracts and validates credentials from r.
func (s *Service) Authenticate(r *http.Request) (string, bool, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", false, errors.New("missing Authorization header")
	}
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := authHeader[7:]
		username, err := s.ValidateJWT(tokenStr)
		return username, false, err
	}
	if strings.HasPrefix(authHeader, "Basic ") {
		username, password, ok := r.BasicAuth()
		if !ok {
			return "", false, errors.New("malformed Basic auth header")
		}
		if err := s.checkRateLimit(r); err != nil {
			return "", false, err
		}
		if err := s.verifyPassword(username, password); err != nil {
			s.recordFailure(r)
			return "", false, errors.New("invalid credentials")
		}
		return username, true, nil
	}
	return "", false, errors.New("unsupported authentication scheme")
}

func (s *Service) verifyPassword(username, password string) error {
	if subtle.ConstantTimeCompare([]byte(username), []byte(s.cfg.AdminUsername)) != 1 {
		return errors.New("unknown user")
	}
	// Plaintext env-var password (legacy / werkzeug fallback).
	if subtle.ConstantTimeCompare([]byte(password), []byte(s.cfg.AdminPassword)) == 1 {
		return nil
	}
	// bcrypt stored hash.
	if s.cfg.AdminPasswordHash != "" {
		if bcrypt.CompareHashAndPassword([]byte(s.cfg.AdminPasswordHash), []byte(password)) == nil {
			return nil
		}
	}
	return errors.New("password mismatch")
}

func (s *Service) checkRateLimit(r *http.Request) error {
	ip := clientIP(r)
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	s.pruneAttempts(ip)
	if len(s.attempts[ip]) >= s.cfg.MaxAttempts {
		return errors.New("too many failed attempts, try again later")
	}
	return nil
}

func (s *Service) recordFailure(r *http.Request) {
	ip := clientIP(r)
	s.attemptsMu.Lock()
	s.attempts[ip] = append(s.attempts[ip], time.Now())
	s.attemptsMu.Unlock()
}

func (s *Service) pruneAttempts(ip string) {
	cutoff := time.Now().Add(-s.cfg.RateLimitWindow)
	var recent []time.Time
	for _, t := range s.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(s.attempts, ip)
	} else {
		s.attempts[ip] = recent
	}
}

// RateLimitSnapshot returns active rate-limited IPs.
func (s *Service) RateLimitSnapshot() []map[string]any {
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	var result []map[string]any
	cutoff := time.Now().Add(-s.cfg.RateLimitWindow)
	for ip, times := range s.attempts {
		var recent []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		if len(recent) > 0 {
			result = append(result, map[string]any{
				"ip":       ip,
				"attempts": len(recent),
				"blocked":  len(recent) >= s.cfg.MaxAttempts,
			})
		}
	}
	return result
}

// ClearRateLimit removes the rate-limit record for ip.
func (s *Service) ClearRateLimit(ip string) bool {
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	if _, ok := s.attempts[ip]; !ok {
		return false
	}
	delete(s.attempts, ip)
	return true
}

// IssueWSToken creates a one-time WebSocket token valid for 2 minutes.
func (s *Service) IssueWSToken(username string) string {
	token := secureToken()
	s.wsTokenMu.Lock()
	s.wsTokens[token] = wsEntry{username: username, expiry: time.Now().Add(2 * time.Minute)}
	s.wsTokenMu.Unlock()
	return token
}

// ValidateWSToken consumes a one-time token and returns the username.
func (s *Service) ValidateWSToken(token string) (string, bool) {
	s.wsTokenMu.Lock()
	defer s.wsTokenMu.Unlock()
	entry, ok := s.wsTokens[token]
	if !ok || time.Now().After(entry.expiry) {
		delete(s.wsTokens, token)
		return "", false
	}
	delete(s.wsTokens, token)
	return entry.username, true
}

func secureToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based token (less secure but no panic)
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(b)
}

// trustedProxy checks if the remote address is a private/Docker network
// that we trust to set X-Forwarded-For correctly.
func trustedProxy(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	// Trust: loopback, Docker bridge (172.16-31.x.x), RFC1918
	trusted := []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"}
	for _, cidr := range trusted {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	// Only trust X-Forwarded-For from known reverse proxies (nginx, Docker network)
	if trustedProxy(r.RemoteAddr) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			return strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])
		}
		if fwd := r.Header.Get("X-Real-IP"); fwd != "" {
			return strings.TrimSpace(fwd)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Service) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.jwtBlacklistMu.Lock()
		for k, exp := range s.jwtBlacklist {
			if now.After(exp) {
				delete(s.jwtBlacklist, k)
			}
		}
		s.jwtBlacklistMu.Unlock()

		s.wsTokenMu.Lock()
		for k, e := range s.wsTokens {
			if now.After(e.expiry) {
				delete(s.wsTokens, k)
			}
		}
		s.wsTokenMu.Unlock()
	}
}
