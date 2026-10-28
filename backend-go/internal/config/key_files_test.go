package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A present but malformed .enc_key is not the same as a missing one. The loader
// used to generate a new key and write it over the file, destroying the only
// copy that could decrypt the stored secrets. It must be reported and kept.
func TestStoredEncKeyRefusesAMalformedFileAndKeepsIt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".enc_key")

	if key, err := storedEncKey(p); err != nil || key != "" {
		t.Fatalf("missing file: got %q, %v; want empty and no error (generate)", key, err)
	}

	good := strings.Repeat("ab", 32)
	if err := os.WriteFile(p, []byte(good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if key, err := storedEncKey(p); err != nil || key != good {
		t.Fatalf("valid file: got %q, %v", key, err)
	}

	for name, content := range map[string]string{
		"truncated":   good[:63],
		"not hex":     strings.Repeat("zz", 32),
		"extra bytes": good + "ff",
		"empty":       "",
	} {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		key, err := storedEncKey(p)
		if err == nil {
			t.Errorf("%s: accepted as %q; a malformed key file must be refused", name, key)
			continue
		}
		if !strings.Contains(err.Error(), p) {
			t.Errorf("%s: the error does not name the file: %v", name, err)
		}
		if got, _ := os.ReadFile(p); string(got) != content {
			t.Errorf("%s: the file was changed to %q", name, got)
		}
	}
}

// A malformed .jwt_secret only costs the open sessions, so a new secret is
// generated, but the old file is moved aside rather than overwritten.
func TestMalformedJWTSecretIsSetAsideNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATABASE_PATH", filepath.Join(dir, "spm.db"))
	t.Setenv("SECRET_KEY", "")
	if err := os.WriteFile(filepath.Join(dir, ".jwt_secret"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}

	if s := loadOrGenerateSecret(); len(s) < 32 {
		t.Fatalf("no usable secret generated: %q", s)
	}
	aside, _ := filepath.Glob(filepath.Join(dir, ".jwt_secret.rejected-*"))
	if len(aside) != 1 {
		t.Fatalf("want one .jwt_secret.rejected-* file, got %v", aside)
	}
	if got, _ := os.ReadFile(aside[0]); string(got) != "short" {
		t.Errorf("the set-aside file holds %q, want the original content", got)
	}
}
