package config

import (
	"os"
	"path/filepath"
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

// SECURE-CONF-01: an operator-supplied ENCRYPTION_KEY must be validated, never
// silently discarded in favour of a generated one.
func TestEncryptionKeyError(t *testing.T) {
	valid := strings.Repeat("ab", 32) // 64 hex chars -> 32 bytes
	cases := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid 32-byte hex", valid, false},
		{"truncated by one", valid[:63], true},
		{"one char too long", valid + "c", true},
		{"right length, not hex", strings.Repeat("z", 64), true},
		{"empty", "", true},
		{"16 bytes", strings.Repeat("ab", 16), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := encryptionKeyError(tc.key); (err != nil) != tc.wantErr {
				t.Errorf("encryptionKeyError(%d chars) error = %v, wantErr %v", len(tc.key), err, tc.wantErr)
			}
		})
	}
}

// SECURE-CONF-01 (wiring): a valid operator-supplied ENCRYPTION_KEY must be
// returned as-is. The finding was that a key failing the length test was
// silently discarded in favour of a file or a generated key, so the positive
// path is what proves the env value is honoured rather than dropped.
func TestLoadOrGenerateEncKeyHonoursSuppliedKey(t *testing.T) {
	want := strings.Repeat("ab", 32)
	t.Setenv("ENCRYPTION_KEY", want)
	if got := loadOrGenerateEncKey(); got != want {
		t.Errorf("supplied ENCRYPTION_KEY was not used: got %q (len %d), want the supplied key", got, len(got))
	}
}

// SECURE-CONF-04: the JWT secret and the encryption key must live beside the
// database, not at a hardcoded /data. Relocating DATABASE_PATH used to leave
// them behind, and every restart then rotated both — invalidating every session
// and making previously encrypted settings undecryptable.
func TestSecretsFollowTheDatabaseDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATABASE_PATH", filepath.Join(dir, "custom", "spm.db"))
	t.Setenv("SECRET_KEY", "")
	t.Setenv("ENCRYPTION_KEY", "")

	if got, want := stateDir(), filepath.Join(dir, "custom"); got != want {
		t.Fatalf("stateDir() = %q, want %q", got, want)
	}

	secret := loadOrGenerateSecret()
	encKey := loadOrGenerateEncKey()
	if secret == "" || encKey == "" {
		t.Fatal("keys were not generated")
	}
	for _, name := range []string{".jwt_secret", ".enc_key"} {
		p := filepath.Join(dir, "custom", name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was not persisted beside the database: %v", name, err)
		}
	}

	// Second load must reuse them, not rotate.
	if loadOrGenerateSecret() != secret {
		t.Error("JWT secret rotated on the second load — every session would be invalidated on restart")
	}
	if loadOrGenerateEncKey() != encKey {
		t.Error("encryption key rotated on the second load — encrypted settings would become undecryptable")
	}
}
