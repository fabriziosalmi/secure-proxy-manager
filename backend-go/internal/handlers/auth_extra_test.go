package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthHandlers_ChangePassword_Failures(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAuthHandlers(db, svc, cfg, nil, nil)

	// Short password
	body, _ := json.Marshal(map[string]string{
		"current_password": "admin-12345",
		"new_password":     "short",
	})
	r := httptest.NewRequest("POST", "/api/change-password", bytes.NewBuffer(body))
	r = withUserContext(r, "admin")
	w := httptest.NewRecorder()
	h.ChangePassword(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for short password, got %d", w.Code)
	}

	// No number/special
	body, _ = json.Marshal(map[string]string{
		"current_password": "admin-12345",
		"new_password":     "passwordonly",
	})
	r = httptest.NewRequest("POST", "/api/change-password", bytes.NewBuffer(body))
	r = withUserContext(r, "admin")
	w = httptest.NewRecorder()
	h.ChangePassword(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for weak password, got %d", w.Code)
	}

	// Wrong current password
	body, _ = json.Marshal(map[string]string{
		"current_password": "wrong",
		"new_password":     "NewPassword123!",
	})
	r = httptest.NewRequest("POST", "/api/change-password", bytes.NewBuffer(body))
	r = withUserContext(r, "admin")
	w = httptest.NewRecorder()
	h.ChangePassword(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for wrong current password, got %d", w.Code)
	}
}

func TestAuthHandlers_Login_Failures(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAuthHandlers(db, svc, cfg, nil, nil)

	// Missing credentials
	body, _ := json.Marshal(map[string]string{"username": ""})
	r := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.Login(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing credentials, got %d", w.Code)
	}
}
