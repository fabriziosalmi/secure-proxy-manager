package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
	"github.com/go-chi/chi/v5"
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
	if w.Code != http.StatusOK {
		t.Errorf("AddIPWhitelist failed: %d", w.Code)
	}

	// 2. AddDomain
	body, _ = json.Marshal(map[string]string{"domain": "example.com", "description": "test"})
	r = httptest.NewRequest("POST", "/api/blacklists/domain", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.AddDomain(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("AddDomain failed: %d", w.Code)
	}

	// 3. AddDomainWhitelist
	body, _ = json.Marshal(map[string]string{"domain": "goodsite.com", "description": "test"})
	r = httptest.NewRequest("POST", "/api/blacklists/domain-whitelist", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.AddDomainWhitelist(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("AddDomainWhitelist failed: %d", w.Code)
	}

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
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for success, got %d", w.Code)
	}

	// Validation Failure (empty countries)
	body, _ = json.Marshal(models.ImportGeoBlacklistRequest{Countries: []string{}})
	r = httptest.NewRequest("POST", "/api/blacklists/import-geo", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.ImportGeo(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for empty, got %d", w.Code)
	}

	// Fetch Failure (unreachable country)
	body, _ = json.Marshal(models.ImportGeoBlacklistRequest{Countries: []string{"XX"}})
	r = httptest.NewRequest("POST", "/api/blacklists/import-geo", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.ImportGeo(w, r)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 for failure, got %d", w.Code)
	}

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
	if w.Code != http.StatusGone {
		t.Errorf("Expected 410, got %d", w.Code)
	}

	r = httptest.NewRequest("POST", "/api/blacklists/import/domain", nil)
	w = httptest.NewRecorder()
	h.ImportDomainLegacy(w, r)
	if w.Code != http.StatusGone {
		t.Errorf("Expected 410, got %d", w.Code)
	}
}

// SECURE-DOM-01: the max=50 the model declares must actually be enforced, and
// duplicates must be collapsed — without both, one request drove two 30s
// outbound fetches per element with no bound.
func TestImportGeo_EnforcesCountryBound(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewBlacklistHandlers(db, cfg)

	many := make([]string, 51)
	for i := range many {
		many[i] = "it"
	}
	body, _ := json.Marshal(map[string]any{"countries": many})
	w := httptest.NewRecorder()
	h.ImportGeo(w, httptest.NewRequest("POST", "/api/ip-blacklist/import-geo", bytes.NewBuffer(body)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for %d countries (max %d), got %d: %s",
			len(many), maxGeoCountries, w.Code, w.Body.String())
	}
}

// SECURE-INPT-01: the accepted import size must sit below the container's
// memory budget, or the process is OOM-killed before the bound can fire.
func TestImportSizeCapIsBelowContainerBudget(t *testing.T) {
	const containerLimitBytes = 128 * 1024 * 1024 // compose: memory: 128M
	if maxImportSize >= containerLimitBytes {
		t.Errorf("maxImportSize (%d) >= container memory limit (%d): the cap can never fire",
			maxImportSize, containerLimitBytes)
	}
}

// SECURE-PERF-01. The geo import fetched up to 50 country feeds sequentially
// inside the request goroutine at a 30-second timeout each, against a server
// WriteTimeout of 60 seconds — so a large import outlived its own response
// deadline while continuing to insert rows, and the operator was told it failed
// for work that had been done.
//
// This asserts the fetches overlap. A slow server plus a wall-clock bound is the
// only way to show concurrency; the margin is wide enough not to be flaky.
func TestImportGeoFetchesConcurrently(t *testing.T) {
	const (
		countries = 16
		delay     = 120 * time.Millisecond
	)
	var inFlight, peak int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		time.Sleep(delay)
		atomic.AddInt32(&inFlight, -1)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer srv.Close()

	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.GeoIPURL = srv.URL
	h := NewBlacklistHandlers(db, cfg)

	list := make([]string, 0, countries)
	for i := 0; i < countries; i++ {
		list = append(list, string(rune('a'+i/26))+string(rune('a'+i%26)))
	}
	body, _ := json.Marshal(models.ImportGeoBlacklistRequest{Countries: list})

	start := time.Now()
	rec := httptest.NewRecorder()
	h.ImportGeo(rec, withUserContext(httptest.NewRequest(http.MethodPost, "/api/blacklists/import-geo", bytes.NewReader(body)), "admin"))
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("import returned %d: %s", rec.Code, rec.Body.String())
	}
	sequential := time.Duration(countries) * delay
	if elapsed >= sequential {
		t.Errorf("the fetches were sequential: %v for %d feeds at %v each (sequential would be %v)",
			elapsed, countries, delay, sequential)
	}
	if p := atomic.LoadInt32(&peak); p < 2 {
		t.Errorf("peak concurrent fetches was %d — the requests did not overlap", p)
	} else {
		t.Logf("peak concurrent fetches: %d, elapsed %v vs %v sequential", p, elapsed, sequential)
	}
}
