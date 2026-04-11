package main

import (
	"os"
	"path/filepath"
	"testing"
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
