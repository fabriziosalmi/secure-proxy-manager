package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
)

func TestBlacklistHandlers_Register(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewBlacklistHandlers(db, cfg)
	r := chi.NewRouter()
	authMW := func(next http.Handler) http.Handler { return next }
	h.Register(r, authMW)
}

func TestBlacklistHandlers_AdditionalAdds(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewBlacklistHandlers(db, cfg)

	// 1. AddIPWhitelist
	body, _ := json.Marshal(map[string]string{"ip": "1.2.3.4", "description": "test"})
	r := httptest.NewRequest("POST", "/api/blacklists/ip-whitelist", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.AddIPWhitelist(w, r)
	if w.Code != http.StatusOK { t.Errorf("AddIPWhitelist failed: %d", w.Code) }

	// 2. AddDomain
	body, _ = json.Marshal(map[string]string{"domain": "example.com", "description": "test"})
	r = httptest.NewRequest("POST", "/api/blacklists/domain", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.AddDomain(w, r)
	if w.Code != http.StatusOK { t.Errorf("AddDomain failed: %d", w.Code) }

	// 3. AddDomainWhitelist
	body, _ = json.Marshal(map[string]string{"domain": "goodsite.com", "description": "test"})
	r = httptest.NewRequest("POST", "/api/blacklists/domain-whitelist", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.AddDomainWhitelist(w, r)
	if w.Code != http.StatusOK { t.Errorf("AddDomainWhitelist failed: %d", w.Code) }

	// Allow async export to finish to prevent TempDir cleanup failures
	time.Sleep(100 * time.Millisecond)
}

func TestBlacklistHandlers_ImportGeo(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	// Mock GeoIP data source
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cc := r.URL.Query().Get("cc")
		if cc == "it" {
			fmt.Fprintln(w, "1.2.3.0/24")
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	cfg.GeoIPURL = ts.URL

	h := NewBlacklistHandlers(db, cfg)

	// Success case
	body, _ := json.Marshal(models.ImportGeoBlacklistRequest{Countries: []string{"IT"}})
	r := httptest.NewRequest("POST", "/api/blacklists/import-geo", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.ImportGeo(w, r)
	if w.Code != http.StatusOK { t.Errorf("Expected 200 for success, got %d", w.Code) }

	// Validation Failure (empty countries)
	body, _ = json.Marshal(models.ImportGeoBlacklistRequest{Countries: []string{}})
	r = httptest.NewRequest("POST", "/api/blacklists/import-geo", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.ImportGeo(w, r)
	if w.Code != http.StatusBadRequest { t.Errorf("Expected 400 for empty, got %d", w.Code) }

	// Fetch Failure (unreachable country)
	body, _ = json.Marshal(models.ImportGeoBlacklistRequest{Countries: []string{"XX"}})
	r = httptest.NewRequest("POST", "/api/blacklists/import-geo", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.ImportGeo(w, r)
	if w.Code != http.StatusBadGateway { t.Errorf("Expected 502 for failure, got %d", w.Code) }

	// Allow async export to finish to prevent TempDir cleanup failures
	time.Sleep(100 * time.Millisecond)
}

func TestBlacklistHandlers_Legacy(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewBlacklistHandlers(db, cfg)

	r := httptest.NewRequest("POST", "/api/blacklists/import/ip", nil)
	w := httptest.NewRecorder()
	h.ImportIPLegacy(w, r)
	if w.Code != http.StatusGone { t.Errorf("Expected 410, got %d", w.Code) }

	r = httptest.NewRequest("POST", "/api/blacklists/import/domain", nil)
	w = httptest.NewRecorder()
	h.ImportDomainLegacy(w, r)
	if w.Code != http.StatusGone { t.Errorf("Expected 410, got %d", w.Code) }
}
