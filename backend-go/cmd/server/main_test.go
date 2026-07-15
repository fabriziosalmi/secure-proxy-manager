package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/gorilla/websocket"
)

func TestRun(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	logPath := filepath.Join(tmpDir, "access.log")
	_ = os.WriteFile(logPath, []byte("test"), 0644)

	os.Setenv("TEST_MODE", "true")
	os.Setenv("BASIC_AUTH_USERNAME", "admin")
	os.Setenv("BASIC_AUTH_PASSWORD", "admin-12345")
	os.Setenv("SECRET_KEY", "test-secret-key-12345678901234567890")
	os.Setenv("DATABASE_PATH", dbPath)
	os.Setenv("LOG_PATH", logPath)
	os.Setenv("CONFIG_DIR", tmpDir)
	os.Setenv("PORT", "5005")

	defer func() {
		os.Unsetenv("TEST_MODE")
		os.Unsetenv("BASIC_AUTH_USERNAME")
		os.Unsetenv("BASIC_AUTH_PASSWORD")
		os.Unsetenv("SECRET_KEY")
		os.Unsetenv("DATABASE_PATH")
		os.Setenv("LOG_PATH", "/logs/access.log")
		os.Unsetenv("CONFIG_DIR")
		os.Unsetenv("PORT")
	}()

	err := run()
	if err != nil {
		t.Errorf("run() failed: %v", err)
	}
}

// TestWsTokenFromSubprotocol verifies the token extraction helper.
func TestWsTokenFromSubprotocol(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		wantTok  string
	}{
		{
			name:    "valid subprotocol",
			header:  "spm-ws-token.abc123",
			wantTok: "abc123",
		},
		{
			name:    "multiple subprotocols, token first",
			header:  "spm-ws-token.deadbeef, other-proto",
			wantTok: "deadbeef",
		},
		{
			name:    "multiple subprotocols, token second",
			header:  "other-proto, spm-ws-token.cafebabe",
			wantTok: "cafebabe",
		},
		{
			name:    "missing subprotocol returns empty",
			header:  "other-proto",
			wantTok: "",
		},
		{
			name:    "no subprotocol header returns empty",
			header:  "",
			wantTok: "",
		},
		{
			name:    "prefix only (no token value) returns empty",
			header:  "spm-ws-token.",
			wantTok: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/api/ws/logs", nil)
			if tc.header != "" {
				req.Header.Set("Sec-WebSocket-Protocol", tc.header)
			}
			got := wsTokenFromSubprotocol(req)
			if got != tc.wantTok {
				t.Errorf("wsTokenFromSubprotocol() = %q, want %q", got, tc.wantTok)
			}
		})
	}
}

// newTestAuthService builds a minimal auth.Service backed by a temp SQLite DB.
func newTestAuthService(t *testing.T) (*auth.Service, *config.Config, *sql.DB) {
	t.Helper()
	tmpDir := t.TempDir()
	db, err := database.Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	adminPass := "admin-12345"
	adminHash, _ := auth.HashPassword(adminPass)
	if err := database.Init(db, "admin", adminHash); err != nil {
		t.Fatalf("init db: %v", err)
	}
	cfg := &config.Config{
		ConfigDir:         tmpDir,
		AdminUsername:     "admin",
		AdminPassword:     adminPass,
		AdminPasswordHash: adminHash,
		SecretKey:         "test-secret-key-12345678901234567890",
		JWTExpireDuration: 1 * time.Hour,
		MaxAttempts:       5,
		RateLimitWindow:   time.Minute,
	}
	return auth.NewService(cfg, db), cfg, db
}

// TestWSLogsSubprotocolAuth exercises the WebSocket auth middleware directly:
//   - valid token in Sec-WebSocket-Protocol → upgrade succeeds
//   - missing subprotocol                  → 401
//   - invalid/expired token                → 401
//   - legacy query-string token            → 401 (no longer accepted)
func TestWSLogsSubprotocolAuth(t *testing.T) {
	authSvc, _, db := newTestAuthService(t)
	defer db.Close()

	// Build a minimal upgrader + middleware that mirrors run().
	upgrader := websocket.Upgrader{
		Subprotocols: []string{"spm-ws-token"},
		CheckOrigin:  func(*http.Request) bool { return true },
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token := wsTokenFromSubprotocol(req)
		if token == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		if _, ok := authSvc.ValidateWSToken(token); !ok {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, req, http.Header{
			"Sec-WebSocket-Protocol": []string{"spm-ws-token"},
		})
		if err != nil {
			return
		}
		conn.Close()
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	t.Run("valid token in subprotocol connects", func(t *testing.T) {
		tok := authSvc.IssueWSToken("admin")
		dialer := websocket.Dialer{}
		conn, resp, err := dialer.Dial(wsURL, http.Header{
			"Sec-WebSocket-Protocol": []string{fmt.Sprintf("spm-ws-token.%s", tok)},
		})
		if err != nil {
			t.Fatalf("expected successful upgrade, got %v (status %v)", err, resp)
		}
		conn.Close()
	})

	t.Run("missing subprotocol returns 401", func(t *testing.T) {
		_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if resp == nil || resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %v", resp)
		}
	})

	t.Run("invalid token in subprotocol returns 401", func(t *testing.T) {
		_, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{
			"Sec-WebSocket-Protocol": []string{"spm-ws-token.deadbeefdeadbeef"},
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if resp == nil || resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %v", resp)
		}
	})

	t.Run("query-string token is not accepted", func(t *testing.T) {
		tok := authSvc.IssueWSToken("admin")
		_, resp, err := websocket.DefaultDialer.Dial(wsURL+"?token="+tok, nil)
		if err == nil {
			t.Fatal("expected error, got nil (query-string token must not be accepted)")
		}
		if resp == nil || resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %v", resp)
		}
	})
}

