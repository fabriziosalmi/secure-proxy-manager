package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A changed password has to be the one that works, and the old one has to stop.
//
// #230: the settings page reported "Password changed successfully", the new
// password was refused and the old one kept working. ChangePassword writes the
// new bcrypt hash to the users table, but authentication compared against
// cfg.AdminPasswordHash, a copy read from the database once during startup and
// never refreshed. So the rotation was recorded, acknowledged, and had no
// effect until the container was restarted.
//
// A credential rotation that reports success without taking effect is worse
// than one that fails: the operator believes the old password is retired.
func TestChangedPasswordIsTheOneThatWorks(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	const (
		oldPassword = "admin-12345"
		newPassword = "Str0nger-pass!"
	)

	h := NewAuthHandlers(db, svc, cfg, nil, nil)

	body, _ := json.Marshal(map[string]string{
		"current_password": oldPassword,
		"new_password":     newPassword,
	})
	req := withUserContext(
		httptest.NewRequest(http.MethodPost, "/api/change-password", bytes.NewReader(body)),
		"admin",
	)
	rec := httptest.NewRecorder()
	h.ChangePassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password returned %d: %s", rec.Code, rec.Body.String())
	}

	authenticate := func(password string) bool {
		r := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
		r.SetBasicAuth("admin", password)
		_, ok, _ := svc.Authenticate(r)
		return ok
	}

	if !authenticate(newPassword) {
		t.Error("the new password is refused: the change was reported as successful " +
			"and did not take effect")
	}
	if authenticate(oldPassword) {
		t.Error("the old password still works: it was not retired by the change")
	}
}

// A password store that cannot be read refuses authentication rather than
// falling back to the copy taken at startup. That copy may hold a password the
// operator has already rotated out, and accepting it because the database is
// briefly unavailable would undo the rotation exactly when nobody is watching.
// Every other endpoint needs the database too, and /api/ready reports unready
// for the same condition.
func TestAuthenticationIsRefusedWhenTheHashCannotBeRead(t *testing.T) {
	db, svc, _, cleanup := setupTestDB(t)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	r.SetBasicAuth("admin", "admin-12345")
	if _, ok, _ := svc.Authenticate(r); !ok {
		t.Fatal("the correct password should authenticate before the table is dropped")
	}

	if _, err := db.Exec("DROP TABLE users"); err != nil {
		t.Fatalf("could not drop users: %v", err)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	r2.SetBasicAuth("admin", "admin-12345")
	if _, ok, _ := svc.Authenticate(r2); ok {
		t.Error("authentication succeeded against a password store that cannot be read")
	}
}

// First boot, before the seed has written a hash: the environment password is
// still accepted. This is the path that lets an operator in on a fresh install.
func TestEnvironmentPasswordStillWorksBeforeTheHashIsSeeded(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	if _, err := db.Exec("UPDATE users SET password='' WHERE username='admin'"); err != nil {
		t.Fatalf("could not clear the hash: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	r.SetBasicAuth("admin", cfg.AdminPassword)
	if _, ok, _ := svc.Authenticate(r); !ok {
		t.Error("the environment password is refused with no hash stored yet")
	}
}
