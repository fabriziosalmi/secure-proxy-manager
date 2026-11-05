package handlers

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

// ClientSetupHandlers serve what a device needs to use the proxy, without a
// login: /setup is opened on the device being configured, which has no
// dashboard session. The CA certificate used to be downloadable only by a
// signed-in admin, who then had to carry it to every device.
//
// Nothing here is more than a client of the proxy already sees: its address,
// whether it asks for a login (it answers 407), and the SSL-bump CA
// certificate, which Squid presents on every bumped connection. Never the key,
// which is not even mounted in this container.
type ClientSetupHandlers struct {
	db  *sql.DB
	cfg *config.Config
}

func NewClientSetupHandlers(db *sql.DB, cfg *config.Config) *ClientSetupHandlers {
	return &ClientSetupHandlers{db: db, cfg: cfg}
}

// Register mounts both routes without the auth middleware (publicRoutes).
func (h *ClientSetupHandlers) Register(r chi.Router) {
	r.Get("/api/client-setup", h.Info)
	r.Get("/api/client-setup/ca.crt", h.CACert)
}

// ClientSetupCA identifies the CA certificate, so a device owner can compare
// it with what the dashboard shows before trusting a file fetched over HTTP.
type ClientSetupCA struct {
	SHA256   string `json:"sha256"`
	NotAfter string `json:"not_after"`
}

type ClientSetupInfo struct {
	ProxyIP   string `json:"proxy_ip"`
	ProxyAuth bool   `json:"proxy_auth"`
	// Inspection is bump, peek or off. Only bump needs the CA on the device:
	// peek reads the TLS handshake and decrypts nothing.
	Inspection string         `json:"inspection"`
	CA         *ClientSetupCA `json:"ca"`
}

func (h *ClientSetupHandlers) Info(w http.ResponseWriter, _ *http.Request) {
	on := map[string]bool{}
	rows, err := h.db.Query(`SELECT setting_name, setting_value FROM settings WHERE setting_name IN ('ssl_bump_enabled', 'tls_peek_enabled', 'enable_proxy_auth')`)
	if err != nil {
		writeInternalError(w, "client_setup", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			writeInternalError(w, "client_setup", err)
			return
		}
		on[name] = value == "true"
	}
	if err := rows.Err(); err != nil {
		writeInternalError(w, "client_setup", err)
		return
	}
	// The same precedence as the proxy's generator: bump, else peek.
	inspection := "off"
	if on["ssl_bump_enabled"] {
		inspection = "bump"
	} else if on["tls_peek_enabled"] {
		inspection = "peek"
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "data": ClientSetupInfo{
		ProxyIP:    h.cfg.ProxyIP,
		ProxyAuth:  on["enable_proxy_auth"],
		Inspection: inspection,
		CA:         readClientSetupCA(filepath.Join(h.cfg.ConfigDir, "ssl_cert.pem")),
	}})
}

// readClientSetupCA returns nil when there is no certificate or it does not
// parse: the page then offers no download rather than an unusable file.
func readClientSetupCA(path string) *ClientSetupCA {
	// #nosec G304 -- a fixed name under the configured /config directory
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(cert.Raw)
	pairs := make([]string, len(sum))
	for i, b := range sum {
		pairs[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	// The format openssl x509 -fingerprint -sha256 prints, which is what an
	// operator compares it with.
	return &ClientSetupCA{SHA256: strings.Join(pairs, ":"), NotAfter: cert.NotAfter.UTC().Format(time.RFC3339)}
}

// CACert serves the certificate only when it parses, as PEM in a .crt file,
// which Windows, macOS, iOS and Android all open as a certificate to install.
func (h *ClientSetupHandlers) CACert(w http.ResponseWriter, _ *http.Request) {
	path := filepath.Join(h.cfg.ConfigDir, "ssl_cert.pem")
	if readClientSetupCA(path) == nil {
		writeError(w, http.StatusNotFound, "The proxy has no CA certificate yet. It creates one when SSL inspection or TLS peek is turned on.")
		return
	}
	// #nosec G304 -- a fixed name under the configured /config directory
	raw, err := os.ReadFile(path)
	if err != nil {
		writeInternalError(w, "client_setup_ca", err)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=secure-proxy-ca.crt")
	// A rotated CA must not be served from a stale cache.
	w.Header().Set("Cache-Control", "no-store")
	w.Write(raw) //nolint:errcheck
}
