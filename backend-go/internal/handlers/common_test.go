package handlers

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
	"net/http"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

func setupTestDB(t *testing.T) (*sql.DB, *auth.Service, *config.Config, func()) {
	tmpDir := t.TempDir()
	tmpDB := filepath.Join(tmpDir, "test.db")
	db, err := database.Open(tmpDB)
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}

	adminPass := "admin-12345"
	adminHash, _ := auth.HashPassword(adminPass)
	if err := database.Init(db, "admin", adminHash); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}

	// Wait for schema initialization.
	_, _ = db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES (?, ?)", "proxy_host", "localhost")

	cfg := &config.Config{
		ConfigDir:         tmpDir, // Use temporary directory for testing
		AdminUsername:     "admin",
		AdminPassword:     adminPass,
		AdminPasswordHash: adminHash,
		SecretKey:         "test-secret-key-12345678901234567890",
		JWTExpireDuration: 1 * time.Hour,
		MaxAttempts:       5,
		RateLimitWindow:   1 * time.Minute,
		ProxyHost:         "localhost",
		ProxyPort:         "3128",
		WAFURL:            "http://localhost:8080", // Default test URL
		ProxyURL:          "http://localhost:3128",
	}

	svc := auth.NewService(cfg, db)

	cleanup := func() {
		db.Close()
	}

	return db, svc, cfg, cleanup
}

func withUserContext(r *http.Request, username string) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.CtxUsername, username)
	return r.WithContext(ctx)
}
