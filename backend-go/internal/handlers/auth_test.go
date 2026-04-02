package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
)

func TestLoginHandler(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAuthHandlers(db, svc, cfg)

	// Success
	loginReq := models.LoginRequest{Username: "admin", Password: "admin-12345"}
	body, _ := json.Marshal(loginReq)
	r := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.Login(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "success" || resp["access_token"] == "" {
		t.Errorf("Unexpected login response: %v", resp)
	}

	// Failure
	loginReq = models.LoginRequest{Username: "admin", Password: "wrong"}
	body, _ = json.Marshal(loginReq)
	r = httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.Login(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestLogoutHandler(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAuthHandlers(db, svc, cfg)

	r := httptest.NewRequest("POST", "/api/logout", nil)
	ctx := context.WithValue(r.Context(), middleware.CtxUsername, "admin")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Logout(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestChangePasswordHandler(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAuthHandlers(db, svc, cfg)

	// Failure: complexity
	cpReq := models.ChangePasswordRequest{CurrentPassword: "admin-12345", NewPassword: "sh"}
	body, _ := json.Marshal(cpReq)
	r := httptest.NewRequest("POST", "/api/change-password", bytes.NewBuffer(body))
	ctx := context.WithValue(r.Context(), middleware.CtxUsername, "admin")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ChangePassword(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for short password, got %d", w.Code)
	}

	// Success
	cpReq = models.ChangePasswordRequest{CurrentPassword: "admin-12345", NewPassword: "NewPassword123!"}
	body, _ = json.Marshal(cpReq)
	r = httptest.NewRequest("POST", "/api/change-password", bytes.NewBuffer(body))
	r = r.WithContext(ctx)
	w = httptest.NewRecorder()
	h.ChangePassword(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestHealthHandlers(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAuthHandlers(db, svc, cfg)

	r := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	h.Health(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	r = httptest.NewRequest("GET", "/health", nil)
	w = httptest.NewRecorder()
	h.HealthLegacy(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}
