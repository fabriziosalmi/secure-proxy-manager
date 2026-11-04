package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// sslCAStatusFile is written by the proxy's generate_squid_conf.sh on every
// run: whether the CA key is in its own /ssl mount and whether the
// certificate database exists there.
const sslCAStatusFile = "ssl_ca_status.json"

type SSLCAStatus struct {
	KeyIsolated bool
	DB          bool
}

// readSSLCAStatus returns the proxy's record, or nil when there is none or it
// cannot be read.
func readSSLCAStatus(configDir string) *SSLCAStatus {
	raw, err := os.ReadFile(filepath.Join(configDir, sslCAStatusFile)) // #nosec G304 -- fixed name in the config dir
	if err != nil {
		return nil
	}
	var s struct {
		Version     int   `json:"version"`
		KeyIsolated *bool `json:"key_isolated"`
		DB          *bool `json:"db"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Version != 1 || s.KeyIsolated == nil || s.DB == nil {
		return nil
	}
	return &SSLCAStatus{KeyIsolated: *s.KeyIsolated, DB: *s.DB}
}
