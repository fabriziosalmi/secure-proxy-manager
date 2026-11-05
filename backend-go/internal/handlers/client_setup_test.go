package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTestCA puts a self-signed CA and its key in dir, as the proxy does,
// and returns the certificate's DER bytes and expiry.
func writeTestCA(t *testing.T, dir string) ([]byte, time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Date(2028, 12, 12, 10, 35, 45, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "spm test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssl_cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// An older install keeps the key next to the certificate; it must never be served.
	if err := os.WriteFile(filepath.Join(dir, "ssl_key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return der, notAfter
}

func TestClientSetupAnswersWithoutALogin(t *testing.T) {
	denyAuthMW := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	}
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.ProxyIP = "192.0.2.10"
	r := buildFullRouterOn(db, svc, cfg, denyAuthMW)
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	type info struct {
		Data ClientSetupInfo `json:"data"`
	}
	read := func() ClientSetupInfo {
		t.Helper()
		w := get("/api/client-setup")
		if w.Code != http.StatusOK {
			t.Fatalf("GET /api/client-setup without a login: %d %s", w.Code, w.Body)
		}
		var got info
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got.Data
	}
	set := func(name, value string) {
		t.Helper()
		if _, err := db.Exec("UPDATE settings SET setting_value=? WHERE setting_name=?", value, name); err != nil {
			t.Fatal(err)
		}
	}

	got := read()
	if got.ProxyIP != "192.0.2.10" || got.ProxyAuth || got.Inspection != "off" || got.CA != nil {
		t.Errorf("defaults, no CA: %+v", got)
	}
	if w := get("/api/client-setup/ca.crt"); w.Code != http.StatusNotFound {
		t.Errorf("ca.crt with no certificate: %d, want 404", w.Code)
	}

	set("tls_peek_enabled", "true")
	if got := read(); got.Inspection != "peek" {
		t.Errorf("peek on: inspection %q", got.Inspection)
	}
	set("ssl_bump_enabled", "true")
	set("enable_proxy_auth", "true")
	if got := read(); got.Inspection != "bump" || !got.ProxyAuth {
		t.Errorf("bump and peek on, login on: %+v (bump wins, as in the proxy's generator)", got)
	}

	der, notAfter := writeTestCA(t, cfg.ConfigDir)
	sum := sha256.Sum256(der)
	want := strings.TrimSuffix(strings.Join(strings.Split(fmt.Sprintf("% X", sum[:]), " "), ":"), ":")
	got = read()
	if got.CA == nil || got.CA.SHA256 != want || got.CA.NotAfter != notAfter.Format(time.RFC3339) {
		t.Errorf("CA: %+v, want sha256 %s not_after %s", got.CA, want, notAfter.Format(time.RFC3339))
	}

	w := get("/api/client-setup/ca.crt")
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/x-x509-ca-cert" {
		t.Fatalf("ca.crt: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	block, _ := pem.Decode(w.Body.Bytes())
	if block == nil || string(block.Bytes) != string(der) {
		t.Errorf("ca.crt is not the certificate: %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String()+fmt.Sprint(read()), "PRIVATE") {
		t.Errorf("a private key reached a public route")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("ca.crt Cache-Control %q: a rotated CA would be served from a cache", w.Header().Get("Cache-Control"))
	}

	// A file that is not a certificate is neither described nor served.
	if err := os.WriteFile(filepath.Join(cfg.ConfigDir, "ssl_cert.pem"), []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.CA != nil {
		t.Errorf("unparsable certificate described: %+v", got.CA)
	}
	if w := get("/api/client-setup/ca.crt"); w.Code != http.StatusNotFound {
		t.Errorf("unparsable certificate served: %d", w.Code)
	}
}
