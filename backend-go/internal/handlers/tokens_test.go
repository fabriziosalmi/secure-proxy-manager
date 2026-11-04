package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

// tokenRefused are the routes no API token may reach, written here apart
// from auth.TokenAllows so the test does not grade the rule by itself.
var tokenRefused = []string{
	"/api/tokens",
	"/api/change-password",
	"/api/logout",
	"/api/database/export",
	"/api/database/reset",
	"/api/maintenance/backup-config",
	"/api/maintenance/restore-config",
	"/api/internal/",
}

func refusedToTokens(path string) bool {
	for _, p := range tokenRefused {
		if path == strings.TrimSuffix(p, "/") || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

// Every route of the catalogue, with a read and with a write token, through
// the real Auth middleware and the router's own patterns. The handlers given
// authMW are replaced by a stub that answers 204, so nothing runs; the auth
// routes keep their own middleware and handlers. A read token reaches GET and
// HEAD only; neither reaches tokenRefused; nothing else is refused (401 or
// 403).
func TestTokenScopesOnEveryCatalogueRoute(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r := buildFullRouterOn(db, svc, cfg, func(http.Handler) http.Handler { return middleware.Auth(svc)(stub) })

	now := time.Now()
	read, _, err := database.CreateAPIToken(db, "reader", database.ScopeRead, "admin", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	write, _, err := database.CreateAPIToken(db, "writer", database.ScopeWrite, "admin", nil, now)
	if err != nil {
		t.Fatal(err)
	}

	replacer := strings.NewReplacer("{id}", "1", "{name}", "proxy_port", "{ip}", "192.0.2.1", "{preset}", "github")
	matched := map[string]bool{}
	routes := 0
	for _, d := range CatalogueRoutes(r) {
		if !d.Auth {
			continue
		}
		routes++
		refused := refusedToTokens(d.Path)
		for _, p := range tokenRefused {
			if refusedToTokens(d.Path) && strings.HasPrefix(d.Path+"/", strings.TrimSuffix(p, "/")+"/") {
				matched[p] = true
			}
		}
		for _, tc := range []struct {
			scope, value string
		}{{database.ScopeRead, read}, {database.ScopeWrite, write}} {
			want := !refused && (tc.scope == database.ScopeWrite || d.Method == http.MethodGet || d.Method == http.MethodHead)
			req := httptest.NewRequest(d.Method, replacer.Replace(d.Path), nil)
			req.Header.Set("Authorization", "Bearer "+tc.value)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			switch {
			case want && (w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden):
				t.Errorf("%s token refused on %s %s: %d %s", tc.scope, d.Method, d.Path, w.Code, w.Body.String())
			case !want && w.Code != http.StatusForbidden:
				t.Errorf("%s token on %s %s: %d, want 403", tc.scope, d.Method, d.Path, w.Code)
			}
		}
	}
	for _, p := range tokenRefused {
		if !matched[p] {
			t.Errorf("no catalogued route under %s: the list names a route that is gone", p)
		}
	}
	if routes < 100 {
		t.Errorf("only %d authenticated routes walked", routes)
	}
	t.Logf("%d authenticated routes, each with a read and a write token", routes)
}

// tokenRouter is the full router with the real middleware and handlers.
func tokenRouter(t *testing.T) func(method, path, cred, body string) *httptest.ResponseRecorder {
	db, svc, cfg, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	r := buildFullRouterOn(db, svc, cfg, middleware.Auth(svc))
	do := func(method, path, cred, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if cred == "admin" {
			req.SetBasicAuth("admin", "admin-12345")
		} else if cred != "" {
			req.Header.Set("Authorization", "Bearer "+cred)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	return do
}

type createdToken struct {
	Data struct {
		Token     string     `json:"token"`
		ID        string     `json:"id"`
		ExpiresAt *time.Time `json:"expires_at"`
	} `json:"data"`
}

func createToken(t *testing.T, do func(string, string, string, string) *httptest.ResponseRecorder, body string) createdToken {
	t.Helper()
	w := do("POST", "/api/tokens", "admin", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", body, w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response carrying the token value may be cached")
	}
	var c createdToken
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAnAPITokenFromCreationToRevocation(t *testing.T) {
	do := tokenRouter(t)

	reader := createToken(t, do, `{"name":"grafana","scope":"read"}`)
	if reader.Data.ExpiresAt == nil || time.Until(*reader.Data.ExpiresAt) < 89*24*time.Hour || time.Until(*reader.Data.ExpiresAt) > 90*24*time.Hour {
		t.Fatalf("default expiry %v, want 90 days", reader.Data.ExpiresAt)
	}
	if w := do("GET", "/api/settings", reader.Data.Token, ""); w.Code != http.StatusOK {
		t.Errorf("read token GET /api/settings: %d %s", w.Code, w.Body.String())
	}
	if w := do("POST", "/api/ip-blacklist", reader.Data.Token, `{"ip":"203.0.113.9"}`); w.Code != http.StatusForbidden {
		t.Errorf("read token POST /api/ip-blacklist: %d", w.Code)
	}
	if w := do("GET", "/api/tokens", reader.Data.Token, ""); w.Code != http.StatusForbidden {
		t.Errorf("a token listed the tokens: %d", w.Code)
	}

	var session struct {
		Data struct {
			Username  string `json:"username"`
			Via       string `json:"via"`
			ExpiresAt int64  `json:"expires_at"`
		} `json:"data"`
	}
	w := do("GET", "/api/session", reader.Data.Token, "")
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil || w.Code != http.StatusOK {
		t.Fatalf("session: %d %s", w.Code, w.Body.String())
	}
	if session.Data.Username != "token:grafana" || session.Data.Via != "token" || session.Data.ExpiresAt != reader.Data.ExpiresAt.Unix() {
		t.Errorf("session %+v", session.Data)
	}

	// A write token's change is audited under the token's name.
	writer := createToken(t, do, `{"name":"deploy","scope":"write","expires_in_days":7}`)
	if w := do("POST", "/api/ip-blacklist", writer.Data.Token, `{"ip":"203.0.113.9","description":"t"}`); w.Code >= 300 {
		t.Fatalf("write token POST /api/ip-blacklist: %d %s", w.Code, w.Body.String())
	}
	w = do("GET", "/api/audit-log?q=203.0.113.9", "admin", "")
	if !strings.Contains(w.Body.String(), `"username":"token:deploy"`) {
		t.Errorf("the audit does not name the token: %s", w.Body.String())
	}

	// The list shows the use and never a value.
	w = do("GET", "/api/tokens", "admin", "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), reader.Data.Token) || strings.Contains(w.Body.String(), writer.Data.Token) {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var list struct {
		Data []database.APIToken `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &list) //nolint:errcheck
	if len(list.Data) != 2 || list.Data[0].LastUsedAt == nil || list.Data[1].LastUsedAt == nil || list.Data[0].CreatedBy != "admin" {
		t.Errorf("list %+v", list.Data)
	}

	// Revoked, it stops at once.
	if w := do("DELETE", "/api/tokens/"+reader.Data.ID, "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if w := do("GET", "/api/settings", reader.Data.Token, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", w.Code)
	}
	if w := do("DELETE", "/api/tokens/"+reader.Data.ID, "admin", ""); w.Code != http.StatusNotFound {
		t.Errorf("revoked twice: %d", w.Code)
	}
	w = do("GET", "/api/audit-log?q=api_token", "admin", "")
	for _, a := range []string{"create_api_token", "revoke_api_token"} {
		if !strings.Contains(w.Body.String(), a) {
			t.Errorf("no %s in the audit log", a)
		}
	}
}

func TestAnAPITokenIsCreatedOnlyAsAsked(t *testing.T) {
	do := tokenRouter(t)
	never := createToken(t, do, `{"name":"mcp","scope":"read","no_expiry":true}`)
	if never.Data.ExpiresAt != nil {
		t.Errorf("no_expiry gave an expiry %v", never.Data.ExpiresAt)
	}
	for body, want := range map[string]int{
		`{"name":"mcp","scope":"read"}`:                                     http.StatusConflict,
		`{"name":"a","scope":"admin"}`:                                      http.StatusBadRequest,
		`{"name":"","scope":"read"}`:                                        http.StatusBadRequest,
		`{"name":"x<script>","scope":"read"}`:                               http.StatusBadRequest,
		`{"name":"b","scope":"read","expires_in_days":0}`:                   http.StatusBadRequest,
		`{"name":"b","scope":"read","expires_in_days":3651}`:                http.StatusBadRequest,
		`{"name":"b","scope":"read","expires_in_days":30,"no_expiry":true}`: http.StatusBadRequest,
		`not json`: http.StatusBadRequest,
	} {
		if w := do("POST", "/api/tokens", "admin", body); w.Code != want {
			t.Errorf("%s: %d, want %d", body, w.Code, want)
		}
	}
}

func TestExpiredAndGuessedTokensAreRefused(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	r := buildFullRouterOn(db, svc, cfg, middleware.Auth(svc))
	get := func(cred string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/settings", nil)
		req.Header.Set("Authorization", "Bearer "+cred)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	past := time.Now().Add(-time.Hour)
	expired, _, _ := database.CreateAPIToken(db, "old", database.ScopeRead, "admin", &past, time.Now().Add(-48*time.Hour))
	if w := get(expired); w.Code != http.StatusUnauthorized {
		t.Errorf("expired token: %d", w.Code)
	}

	good, tok, _ := database.CreateAPIToken(db, "good", database.ScopeRead, "admin", nil, time.Now())
	if w := get(good); w.Code != http.StatusOK {
		t.Fatalf("good token: %d", w.Code)
	}
	// Wrong guesses count like wrong passwords (MaxAttempts is 5 here, and the
	// expired token above was one): once over, even the right token waits.
	for i := 0; i < 4; i++ {
		get("spm_" + tok.ID + "_guess")
	}
	w := get(good)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "too many failed attempts") {
		t.Errorf("after 5 failures the right token got %d %s", w.Code, w.Body.String())
	}
}
