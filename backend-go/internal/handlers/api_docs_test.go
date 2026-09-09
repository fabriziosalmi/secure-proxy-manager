package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

// buildFullRouter registers every handler group the way main.go does, so the
// catalogue can be compared against the real surface.
func buildFullRouter(t *testing.T) chi.Router {
	t.Helper()
	db, svc, cfg, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)

	r := chi.NewRouter()
	authMW := func(next http.Handler) http.Handler { return next }
	NewAuthHandlers(db, svc, cfg, nil, nil).Register(r)
	NewLogHandlers(db).Register(r, authMW)
	NewSettingsHandlers(db, cfg).Register(r, authMW)
	NewBlacklistHandlers(db, cfg).Register(r, authMW)
	NewSecurityHandlers(db, svc, cfg, nil).Register(r, authMW)
	NewMaintenanceHandlers(db, cfg).Register(r, authMW)
	NewAnalyticsHandlers(db, cfg).Register(r, authMW)
	NewDatabaseHandlers(db).Register(r, authMW)
	NewDNSDetectHandlers(db).Register(r, authMW)
	RegisterAPIDocs(r, authMW)
	return r
}

// SECURE-API-01: the published catalogue must BE the router, not a hand-kept
// copy of it. The original slice had drifted to 63 entries against 81 routes,
// omitting the entire egress-allowlist resource and POST /api/auth/refresh.
func TestAPIDocsCoversEveryRegisteredRoute(t *testing.T) {
	r := buildFullRouter(t)

	registered := map[string]bool{}
	if err := chi.Walk(r.(*chi.Mux), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		registered[method+" "+route] = true
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}

	catalogued := map[string]bool{}
	for _, d := range CatalogueRoutes(r) {
		catalogued[d.Method+" "+d.Path] = true
	}

	for route := range registered {
		if !catalogued[route] {
			t.Errorf("route %s is registered but missing from /api/docs", route)
		}
	}
	if len(catalogued) < len(registered) {
		t.Errorf("catalogue has %d entries for %d registered routes", len(catalogued), len(registered))
	}
	t.Logf("catalogue covers %d routes", len(catalogued))
}

// The endpoints that must never be missing, because a non-browser client
// cannot work without them and they were exactly what the drift dropped.
func TestAPIDocsIncludesTheRoutesTheDriftDropped(t *testing.T) {
	r := buildFullRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/docs", nil))

	var resp struct {
		Data []APIDoc `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	have := map[string]APIDoc{}
	for _, d := range resp.Data {
		have[d.Method+" "+d.Path] = d
	}

	for _, want := range []string{
		"POST /api/auth/refresh",
		"GET /api/egress-allowlist",
		"POST /api/egress-allowlist",
		"PUT /api/settings/{name}",
		"POST /api/waf/test-rule",
		"GET /readyz",
	} {
		if _, ok := have[want]; !ok {
			t.Errorf("%s missing from the catalogue", want)
		}
	}

	// The auth flag must be right, not merely present.
	if d, ok := have["POST /api/auth/login"]; ok && d.Auth {
		t.Error("login is reported as requiring auth")
	}
	if d, ok := have["GET /api/settings"]; ok && !d.Auth {
		t.Error("GET /api/settings is reported as public")
	}
}

// SECURE-API-04: a 500 must not leak the SQLite driver's wording into the
// contractual detail field — it changes with a dependency bump this project's
// changelog would not mention, and a UI cannot map it to anything.
func TestInternalErrorsDoNotLeakDriverText(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewBlacklistHandlers(db, cfg)

	// Drop the table so the insert fails with a driver error.
	if _, err := db.Exec("DROP TABLE ip_blacklist"); err != nil {
		t.Fatalf("drop: %v", err)
	}
	body := `{"ip":"203.0.113.9","description":"x"}`
	w := httptest.NewRecorder()
	h.AddIP(w, httptest.NewRequest("POST", "/api/ip-blacklist", strings.NewReader(body)))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, leak := range []string{"SQL logic error", "no such table", "sqlite", "SQLITE"} {
		if strings.Contains(resp["detail"], leak) {
			t.Errorf("detail leaks driver text (%q): %q", leak, resp["detail"])
		}
	}
	if resp["code"] == "" {
		t.Error("no machine-readable code — a client must branch on prose")
	}
}

// SECURE-API-03: every response carries the contract version, and it is not
// the product build version.
func TestResponsesCarryTheAPIVersion(t *testing.T) {
	r := chi.NewRouter()
	r.Use(middleware.APIVersion)
	r.Get("/x", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))

	got := w.Header().Get("X-API-Version")
	if got == "" {
		t.Fatal("X-API-Version is not set — a caller has nothing stable to assert on")
	}
	if got != config.APIVersion {
		t.Errorf("X-API-Version = %q, want %q", got, config.APIVersion)
	}
	if got == config.AppVersion {
		t.Error("the contract version is the build version — it will churn on releases that change no shape")
	}
}

// SECURE-API-02: every collection endpoint must emit ONE shape — the
// collection under data, the pagination under meta. Three incompatible shapes
// meant no client-side helper could read a list, which is why the frontend
// carried `data?.data ?? data?.logs`.
func TestListEndpointsShareOneShape(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	// Seed something into each collection so the shapes are exercised non-empty.
	for _, q := range []string{
		`INSERT INTO ip_blacklist(ip, description) VALUES('203.0.113.7','x')`,
		`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, destination, status)
		   VALUES(datetime('now'), strftime('%s','now'), '10.0.0.5', 'example.com', 'TCP_DENIED/403')`,
		`INSERT INTO audit_log(username, action, target) VALUES('admin','test','x')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	r := chi.NewRouter()
	authMW := func(next http.Handler) http.Handler { return next }
	NewLogHandlers(db).Register(r, authMW)
	NewBlacklistHandlers(db, cfg).Register(r, authMW)
	NewAnalyticsHandlers(db, cfg).Register(r, authMW)

	for _, path := range []string{
		"/api/logs",
		"/api/ip-blacklist",
		"/api/audit-log",
		"/api/clients/statistics",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}

			var resp struct {
				Status string            `json:"status"`
				Data   []json.RawMessage `json:"data"`
				Meta   *ListMeta         `json:"meta"`
			}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v — the collection is not an array under `data`", err)
			}
			if resp.Status != "success" {
				t.Errorf("status = %q", resp.Status)
			}
			if resp.Data == nil {
				t.Error("`data` is not an array — the collection is nested somewhere else")
			}
			if resp.Meta == nil {
				t.Fatal("`meta` is absent — a client cannot read pagination uniformly")
			}
			if resp.Meta.Total < 0 {
				t.Errorf("meta.total = %d", resp.Meta.Total)
			}
		})
	}
}

// SECURE-AUTH-01. RegisterAPIDocs accepted authMW and never applied it, so the
// catalogue — every route, with a flag naming which need no credentials — was
// served unauthenticated through nginx's `location /api/` proxy.
//
// The middleware here REFUSES, which is what distinguishes this from the
// pass-through used elsewhere in these tests: with a pass-through, an ungated
// route and a gated one both answer 200 and the test proves nothing.
func TestAPIDocsIsGated(t *testing.T) {
	denyAll := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	r := chi.NewRouter()
	RegisterAPIDocs(r, denyAll)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/docs", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/docs bypassed the middleware it was given: got %d, want 401", w.Code)
	}
}
