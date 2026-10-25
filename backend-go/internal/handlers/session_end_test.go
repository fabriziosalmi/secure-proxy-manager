package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Changing the password used to revoke nothing: a session someone had stolen
// kept working. It now ends every earlier session, and the caller gets a fresh
// pair so the session that made the change continues.
func TestChangePasswordEndsEarlierSessionsAndKeepsTheCallers(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAuthHandlers(authStore(db), svc, cfg, nil, nil)

	stolenAccess, _ := svc.IssueJWT("admin")
	stolenRefresh, _ := svc.IssueRefreshToken("admin")

	body, _ := json.Marshal(map[string]string{"current_password": "admin-12345", "new_password": "Str0nger-pass!"})
	rec := httptest.NewRecorder()
	h.ChangePassword(rec, withUserContext(httptest.NewRequest(http.MethodPost, "/api/change-password", bytes.NewReader(body)), "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password returned %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	if _, err := svc.ValidateJWT(stolenAccess); err == nil {
		t.Error("an access token from before the change still works")
	}
	if _, err := svc.ValidateRefreshToken(stolenRefresh); err == nil {
		t.Error("a refresh token from before the change still works")
	}
	if _, err := svc.ValidateJWT(resp["access_token"]); err != nil {
		t.Errorf("the caller's new access token is refused: %v", err)
	}
	if _, err := svc.ValidateRefreshToken(resp["refresh_token"]); err != nil {
		t.Errorf("the caller's new refresh token is refused: %v", err)
	}
}

// Logout revoked only the bearer access token, so a refresh token from the same
// login went on minting new pairs for a week.
func TestLogoutAlsoEndsTheRefreshToken(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAuthHandlers(authStore(db), svc, cfg, nil, nil)

	access, _ := svc.IssueJWT("admin")
	refresh, _ := svc.IssueRefreshToken("admin")
	body, _ := json.Marshal(map[string]string{"refresh_token": refresh})
	req := withUserContext(httptest.NewRequest(http.MethodPost, "/api/logout", bytes.NewReader(body)), "admin")
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	h.Logout(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout returned %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.ValidateJWT(access); err == nil {
		t.Error("the access token survived logout")
	}
	if _, err := svc.ValidateRefreshToken(refresh); err == nil {
		t.Error("the refresh token survived logout")
	}

	// Without a body, logout still works and ends the access token.
	access2, _ := svc.IssueJWT("admin")
	req = withUserContext(httptest.NewRequest(http.MethodPost, "/api/logout", nil), "admin")
	req.Header.Set("Authorization", "Bearer "+access2)
	rec = httptest.NewRecorder()
	h.Logout(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("logout without a body returned %d", rec.Code)
	}
}
