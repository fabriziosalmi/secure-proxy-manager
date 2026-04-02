package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

func TestRequestID(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Header().Get("X-Request-ID") == "" {
		t.Error("X-Request-ID header missing")
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options header mismatch")
	}
}

func TestMaxBodySize(t *testing.T) {
	handler := MaxBodySize(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Too large
	r := httptest.NewRequest("POST", "/", bytes.NewBufferString("too long body"))
	r.Header.Set("Content-Length", "13")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected 413, got %d", w.Code)
	}

	// OK
	r = httptest.NewRequest("POST", "/", bytes.NewBufferString("short"))
	r.Header.Set("Content-Length", "5")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestCORS(t *testing.T) {
	cfg := &config.Config{CORSAllowedOrigins: []string{"http://allowed.com"}}
	handler := CORS(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Allowed origin
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "http://allowed.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Header().Get("Access-Control-Allow-Origin") != "http://allowed.com" {
		t.Error("CORS header not set for allowed origin")
	}

	// Disallowed origin
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "http://evil.com")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS header set for disallowed origin")
	}

	// OPTIONS
	r = httptest.NewRequest("OPTIONS", "/", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("Expected 204 for OPTIONS, got %d", w.Code)
	}
}

func TestAuth(t *testing.T) {
	cfg := &config.Config{
		AdminUsername:   "admin",
		AdminPassword:   "password",
		MaxAttempts:     5,
		RateLimitWindow: 1 * time.Minute,
	}
	authSvc := auth.NewService(cfg)
	handler := Auth(authSvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Unauthorized
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}

	// Authorized (Basic)
	r = httptest.NewRequest("GET", "/", nil)
	r.SetBasicAuth("admin", "password")
	r.RemoteAddr = "127.0.0.1:1234"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}
}
