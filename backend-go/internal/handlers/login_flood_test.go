package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every rate-limited login wrote an audit row and queued a notification, after
// the lockout as well as before it. With no authentication needed, one client
// at nginx's 20 r/s produced about 1.7M audit rows a day and a webhook,
// Gotify or Telegram message per request.
func TestLockedOutLoginsDoNotFloodTheAuditLog(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	notify := make(chan map[string]any, 1000)
	h := NewAuthHandlers(authStore(db), svc, cfg, notify, nil)

	long := strings.Repeat("x", 128)
	for i := 0; i < 200; i++ {
		body, _ := json.Marshal(map[string]string{"username": long, "password": "wrong-guess"})
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		r.RemoteAddr = "203.0.113.77:5555"
		h.Login(httptest.NewRecorder(), r)
	}

	var rows int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='login_failed'").Scan(&rows)
	if max := cfg.MaxAttempts + 1; rows > max {
		t.Errorf("200 failed logins from one address wrote %d audit rows, want at most %d", rows, max)
	}
	if n := len(notify); n > cfg.MaxAttempts+1 {
		t.Errorf("200 failed logins queued %d notifications, want at most %d", n, cfg.MaxAttempts+1)
	}
	var longest int
	_ = db.QueryRow("SELECT COALESCE(MAX(LENGTH(username)),0) FROM audit_log WHERE action='login_failed'").Scan(&longest)
	if longest > 64 {
		t.Errorf("an attacker-chosen username of %d characters was stored", longest)
	}
}
