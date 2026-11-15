// Package cli is the spm command: the management API from a terminal, under
// the dashboard's names. It reads the operations from the OpenAPI document it
// is built with, signs in with an API token, and pins the TLS certificate of a
// server whose certificate no public authority signed.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Config is what spm remembers about the server it talks to.
type Config struct {
	URL   string `json:"url"`
	Token string `json:"token"`
	// Fingerprint is the SHA-256 of the server certificate the person
	// confirmed at spm login, in hex; empty when the certificate is checked
	// against the system's authorities instead.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// configPath is $SPM_CONFIG, or spm/config.json in the user's config directory.
func configPath() (string, error) {
	if p := os.Getenv("SPM_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "spm", "config.json"), nil
}

// errConfigReadable is a config file other users can read: it holds a token.
var errConfigReadable = errors.New("config file readable by other users")

// loadConfig reads the config file; a missing one is an empty Config. A file
// that group or others can read is refused: it holds the API token.
func loadConfig(path string) (Config, error) {
	var c Config
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return c, fmt.Errorf("%w: %s is mode %o; run chmod 600 %s", errConfigReadable, path, info.Mode().Perm(), path)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- the path is the user's own config file
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s is not a spm config file: %w", path, err)
	}
	return c, nil
}

// saveConfig writes the config file with mode 0600, in a directory of mode
// 0700, through a temporary file renamed over the old one.
func saveConfig(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// resolve gives each setting from the first place that has it: the flag, then
// the environment (SPM_URL, SPM_TOKEN), then the config file.
func resolve(file Config, flagURL, flagToken string) Config {
	c := file
	if v := os.Getenv("SPM_URL"); v != "" {
		c.URL = v
	}
	if v := os.Getenv("SPM_TOKEN"); v != "" {
		c.Token = v
	}
	if flagURL != "" {
		c.URL = flagURL
	}
	if flagToken != "" {
		c.Token = flagToken
	}
	return c
}
