package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// With INTERNAL_ALERT_TOKEN unset the WAF reads the token the backend wrote
// into the shared volume, and reads it when it needs it: the backend may write
// it after the WAF has started.
func TestServiceTokenIsReadFromTheSharedFileWhenNeeded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_token")
	t.Setenv("INTERNAL_ALERT_TOKEN", "")
	t.Setenv("BASIC_AUTH_USERNAME", "")
	t.Setenv("BASIC_AUTH_PASSWORD", "")
	t.Setenv("SPM_SERVICE_TOKEN_FILE", path)

	// The management middleware is built before the token exists.
	h := mgmtAuthMiddleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	tok := strings.Repeat("ab", 32)
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/stats", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	h(w, r)
	if w.Code != 204 {
		t.Errorf("management call with the shared token: %d, want 204", w.Code)
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/stats", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	h(w, r)
	if w.Code == 204 {
		t.Error("a wrong token was accepted")
	}

	var sent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	t.Setenv("BACKEND_URL", srv.URL)
	notifyBackend(map[string]interface{}{"event_type": "waf_block"})
	if sent != "Bearer "+tok {
		t.Errorf("alert sent with Authorization %q, want the shared token", sent)
	}
}

// The environment wins over the file.
func TestServiceTokenFromTheEnvironmentWinsInTheWAF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alert_token")
	_ = os.WriteFile(path, []byte(strings.Repeat("cd", 32)), 0o644)
	t.Setenv("SPM_SERVICE_TOKEN_FILE", path)
	t.Setenv("INTERNAL_ALERT_TOKEN", "from-env")
	if got := serviceToken(); got != "from-env" {
		t.Errorf("got %q, want the environment's token", got)
	}
}
