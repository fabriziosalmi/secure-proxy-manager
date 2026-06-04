package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	// Set required environment variables
	os.Setenv("BASIC_AUTH_USERNAME", "testuser")
	os.Setenv("BASIC_AUTH_PASSWORD", "testpass")
	os.Setenv("PORT", "9999")
	os.Setenv("CORS_ALLOWED_ORIGINS", "http://test.com, http://example.com")

	defer func() {
		os.Unsetenv("BASIC_AUTH_USERNAME")
		os.Unsetenv("BASIC_AUTH_PASSWORD")
		os.Setenv("PORT", "")
		os.Setenv("CORS_ALLOWED_ORIGINS", "")
	}()

	cfg := Load()

	if cfg.AdminUsername != "testuser" {
		t.Errorf("Expected testuser, got %s", cfg.AdminUsername)
	}
	if cfg.Port != "9999" {
		t.Errorf("Expected port 9999, got %s", cfg.Port)
	}
	if len(cfg.CORSAllowedOrigins) != 2 {
		t.Errorf("Expected 2 CORS origins, got %d", len(cfg.CORSAllowedOrigins))
	}
}

func TestEnvOrDefault(t *testing.T) {
	os.Setenv("TEST_KEY", "value")
	defer os.Unsetenv("TEST_KEY")

	if got := envOrDefault("TEST_KEY", "default"); got != "value" {
		t.Errorf("envOrDefault(TEST_KEY) = %s, want value", got)
	}
	if got := envOrDefault("NON_EXISTENT", "default"); got != "default" {
		t.Errorf("envOrDefault(NON_EXISTENT) = %s, want default", got)
	}
}

func TestLoadOrGenerateSecret(t *testing.T) {
	// Test from ENV
	os.Setenv("SECRET_KEY", "super-secret-key-12345678901234567890")
	defer os.Unsetenv("SECRET_KEY")

	s := loadOrGenerateSecret()
	if s != "super-secret-key-12345678901234567890" {
		t.Errorf("Expected secret from env, got %s", s)
	}
}

func TestSecretKeyStrengthError(t *testing.T) {
	weak := []struct {
		name   string
		secret string
	}{
		{"known default", "dev_secret_key_change_in_production"},
		{"known default cased", "ChangeMe"},
		{"too short", "abc123"},
		{"low entropy repeat", strings.Repeat("a", 64)},
		{"low entropy few chars", strings.Repeat("ab", 32)},
	}
	for _, tc := range weak {
		if err := secretKeyStrengthError(tc.secret); err == nil {
			t.Errorf("%s: expected error for %q, got nil", tc.name, tc.secret)
		}
	}

	strong := []string{
		"super-secret-key-12345678901234567890",
		"f3a9c1d2e4b5968708172635445362718091a2b3c4d5e6f70819ab2c3d4e5f60", // openssl rand -hex 32
	}
	for _, s := range strong {
		if err := secretKeyStrengthError(s); err != nil {
			t.Errorf("expected %q to be accepted, got error: %v", s, err)
		}
	}
}
