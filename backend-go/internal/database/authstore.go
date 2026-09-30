package database

import (
	"context"
	"database/sql"
	"errors"
)

// AuthStore is the persistence the authentication handlers need: the admin
// password hash, the "default password changed" marker, the audit trail, and a
// readiness probe. It exists so those handlers are given four narrow
// operations instead of the whole *sql.DB, which lets them run any statement
// against any table. The SQL for the users table lives here, next to its schema.
type AuthStore struct{ db *sql.DB }

// NewAuthStore wraps an open database.
func NewAuthStore(db *sql.DB) *AuthStore { return &AuthStore{db: db} }

// PasswordHash returns the stored bcrypt hash for username.
func (s *AuthStore) PasswordHash(username string) (string, error) {
	var stored string
	err := s.db.QueryRow("SELECT password FROM users WHERE username=?", username).Scan(&stored)
	return stored, err
}

// SetPassword replaces the stored hash and records that the initial password
// has been changed.
func (s *AuthStore) SetPassword(username, hash string) error {
	if _, err := s.db.Exec("UPDATE users SET password=? WHERE username=?", hash, username); err != nil {
		return err
	}
	// Best effort, as before: the password is already changed, and a failure to
	// record the marker must not report the change as failed.
	_, _ = s.db.Exec(
		"INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES(?,?)",
		"default_password_changed", "true",
	)
	return nil
}

// Audit writes a best-effort audit log row.
func (s *AuthStore) Audit(username, action, target, details string) {
	Audit(s.db, username, action, target, details)
}

// Ping reports whether the database is reachable and can execute a statement,
// not merely that a connection is open.
func (s *AuthStore) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return errors.New("database unreachable")
	}
	var one int
	if err := s.db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		return errors.New("database query failed")
	}
	return nil
}
