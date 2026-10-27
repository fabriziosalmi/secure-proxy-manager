package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

// sessionTTL is the access token lifetime of the last sessionRig.
var sessionTTL time.Duration

// sessionRig is the auth routes behind the same CORS and CSRF middleware as
// the server, plus a protected route that reads and writes.
func sessionRig(t *testing.T) http.Handler {
	t.Helper()
	db, svc, cfg, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	cfg.CORSAllowedOrigins = []string{"http://localhost:5173"}
	sessionTTL = cfg.JWTExpireDuration
	r := chi.NewRouter()
	r.Use(middleware.CORS(cfg))
	r.Use(middleware.SessionCSRF(cfg))
	NewAuthHandlers(authStore(db), svc, cfg, nil, nil).Register(r)
	ok := func(w http.ResponseWriter, r *http.Request) {
		via, _ := r.Context().Value(middleware.CtxAuthVia).(string)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "via": via})
	}
	r.With(middleware.Auth(svc)).Get("/api/probe", ok)
	r.With(middleware.Auth(svc)).Post("/api/probe", ok)
	return r
}

type reqOpt func(*http.Request)

func withCookie(c *http.Cookie) reqOpt { return func(r *http.Request) { r.AddCookie(c) } }
func withHeader(k, v string) reqOpt    { return func(r *http.Request) { r.Header.Set(k, v) } }

func do(t *testing.T, h http.Handler, method, path, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "spm.example"
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func sessionCookieOf(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			return c
		}
	}
	return nil
}

// cookieLogin signs in as the UI does, through nginx (https).
func cookieLogin(t *testing.T, h http.Handler) (*http.Cookie, map[string]any) {
	t.Helper()
	w := do(t, h, "POST", "/api/auth/login", `{"username":"admin","password":"admin-12345"}`,
		withHeader("X-SPM-Session", "cookie"), withHeader("X-Forwarded-Proto", "https"))
	if w.Code != http.StatusOK {
		t.Fatalf("login answered %d: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	c := sessionCookieOf(t, w)
	if c == nil {
		t.Fatalf("no %s cookie in %v", auth.SessionCookieName, w.Header().Values("Set-Cookie"))
	}
	return c, body
}

func TestCookieLoginSetsAnHttpOnlyStrictCookieAndKeepsTheTokenOutOfTheBody(t *testing.T) {
	h := sessionRig(t)
	c, body := cookieLogin(t, h)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/api" {
		t.Errorf("cookie attributes: HttpOnly=%v Secure=%v SameSite=%v Path=%q", c.HttpOnly, c.Secure, c.SameSite, c.Path)
	}
	if c.MaxAge <= 0 || c.MaxAge > int((sessionTTL+time.Minute).Seconds()) {
		t.Errorf("cookie MaxAge %d, want the token's lifetime", c.MaxAge)
	}
	for _, k := range []string{"access_token", "refresh_token", "token"} {
		if _, ok := body[k]; ok {
			t.Errorf("cookie login body carries %s: %v", k, body)
		}
	}
	if body["username"] != "admin" {
		t.Errorf("username %v", body["username"])
	}
	exp, _ := body["expires_at"].(float64)
	if d := time.Until(time.Unix(int64(exp), 0)); d < sessionTTL-time.Minute || d > sessionTTL+time.Minute {
		t.Errorf("expires_at %v is %v away, want about %v (JWT_EXPIRE_DURATION)", body["expires_at"], d, sessionTTL)
	}
}

func TestCookieLoginOverPlainHTTPIsNotSecure(t *testing.T) {
	h := sessionRig(t)
	w := do(t, h, "POST", "/api/auth/login", `{"username":"admin","password":"admin-12345"}`, withHeader("X-SPM-Session", "cookie"))
	if c := sessionCookieOf(t, w); c == nil || c.Secure {
		t.Fatalf("over the backend's own http port the cookie must exist without Secure: %v", c)
	}
}

func TestLoginWithoutTheSessionHeaderStillReturnsTokens(t *testing.T) {
	h := sessionRig(t)
	w := do(t, h, "POST", "/api/auth/login", `{"username":"admin","password":"admin-12345"}`)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusOK || body["access_token"] == nil || body["refresh_token"] == nil {
		t.Fatalf("API login changed: %d %v", w.Code, body)
	}
	if sessionCookieOf(t, w) != nil {
		t.Fatal("an API login must not set the session cookie")
	}
}

func TestTheSessionCookieAuthenticatesReadsAndCSRFGuardsWrites(t *testing.T) {
	h := sessionRig(t)
	c, _ := cookieLogin(t, h)
	if w := do(t, h, "GET", "/api/probe", "", withCookie(c)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"via":"cookie"`) {
		t.Fatalf("GET with the cookie: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, h, "GET", "/api/probe", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("GET without credentials: %d", w.Code)
	}
	csrf := withHeader("X-Requested-With", "spm")
	for _, tc := range []struct {
		name string
		opts []reqOpt
		want int
	}{
		{"cookie, no CSRF header", []reqOpt{withCookie(c)}, http.StatusForbidden},
		{"cookie, wrong CSRF header", []reqOpt{withCookie(c), withHeader("X-Requested-With", "XMLHttpRequest")}, http.StatusForbidden},
		{"cookie, CSRF header, another site", []reqOpt{withCookie(c), csrf, withHeader("Origin", "https://evil.example")}, http.StatusForbidden},
		{"cookie, CSRF header, this host over http", []reqOpt{withCookie(c), csrf, withHeader("Origin", "http://spm.example")}, http.StatusForbidden},
		{"cookie, CSRF header, this host over https on the UI port", []reqOpt{withCookie(c), csrf, withHeader("Origin", "https://spm.example:8443")}, http.StatusOK},
		{"cookie, CSRF header, an allowed origin", []reqOpt{withCookie(c), csrf, withHeader("Origin", "http://localhost:5173")}, http.StatusOK},
		{"cookie, CSRF header, no Origin", []reqOpt{withCookie(c), csrf}, http.StatusOK},
		{"Basic, no CSRF header (API client)", []reqOpt{withHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:admin-12345")))}, http.StatusOK},
	} {
		if w := do(t, h, "POST", "/api/probe", "{}", tc.opts...); w.Code != tc.want {
			t.Errorf("%s: %d, want %d (%s)", tc.name, w.Code, tc.want, w.Body.String())
		}
	}
}

func TestCookieLogoutRevokesTheTokenAndClearsTheCookie(t *testing.T) {
	h := sessionRig(t)
	c, _ := cookieLogin(t, h)
	w := do(t, h, "POST", "/api/logout", "{}", withCookie(c), withHeader("X-Requested-With", "spm"), withHeader("X-Forwarded-Proto", "https"))
	if w.Code != http.StatusOK {
		t.Fatalf("logout %d: %s", w.Code, w.Body.String())
	}
	if cleared := sessionCookieOf(t, w); cleared == nil || cleared.MaxAge >= 0 || cleared.Value != "" {
		t.Errorf("logout did not clear the cookie: %v", cleared)
	}
	// A copy of the old cookie is refused: the token was revoked.
	if w := do(t, h, "GET", "/api/probe", "", withCookie(c)); w.Code != http.StatusUnauthorized {
		t.Fatalf("the cookie still authenticates after logout: %d", w.Code)
	}
}

func TestCookiePasswordChangeRenewsTheCookieAndEndsTheOldOne(t *testing.T) {
	h := sessionRig(t)
	c, _ := cookieLogin(t, h)
	w := do(t, h, "POST", "/api/change-password", `{"current_password":"admin-12345","new_password":"n3w-Passw0rd!x"}`,
		withCookie(c), withHeader("X-Requested-With", "spm"), withHeader("X-Forwarded-Proto", "https"))
	if w.Code != http.StatusOK {
		t.Fatalf("change-password %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), "refresh_token") {
		t.Errorf("tokens in the body of a cookie session: %s", w.Body.String())
	}
	fresh := sessionCookieOf(t, w)
	if fresh == nil || fresh.Value == "" || fresh.Value == c.Value || !fresh.HttpOnly {
		t.Fatalf("no new session cookie: %v", fresh)
	}
	if w := do(t, h, "GET", "/api/probe", "", withCookie(c)); w.Code != http.StatusUnauthorized {
		t.Errorf("the old cookie still works after the password change: %d", w.Code)
	}
	if w := do(t, h, "GET", "/api/probe", "", withCookie(fresh)); w.Code != http.StatusOK {
		t.Errorf("the new cookie does not work: %d", w.Code)
	}
}

func TestSessionReportsWhoHowAndUntilWhen(t *testing.T) {
	h := sessionRig(t)
	c, login := cookieLogin(t, h)
	w := do(t, h, "GET", "/api/session", "", withCookie(c))
	var got struct {
		Data struct {
			Username  string   `json:"username"`
			Via       string   `json:"via"`
			ExpiresAt *float64 `json:"expires_at"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != http.StatusOK || got.Data.Username != "admin" || got.Data.Via != "cookie" || got.Data.ExpiresAt == nil || *got.Data.ExpiresAt != login["expires_at"] {
		t.Fatalf("cookie session: %d %s", w.Code, w.Body.String())
	}
	basic := withHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:admin-12345")))
	w = do(t, h, "GET", "/api/session", "", basic)
	if !strings.Contains(w.Body.String(), `"via":"basic"`) || !strings.Contains(w.Body.String(), `"expires_at":null`) {
		t.Fatalf("basic session: %s", w.Body.String())
	}
	if w := do(t, h, "GET", "/api/session", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", w.Code)
	}
}

func TestCORSNoLongerEchoesThisHostOverPlainHTTP(t *testing.T) {
	h := sessionRig(t)
	if w := do(t, h, "OPTIONS", "/api/probe", "", withHeader("Origin", "http://spm.example")); w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("http://<host> echoed: %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
	w := do(t, h, "OPTIONS", "/api/probe", "", withHeader("Origin", "https://spm.example"))
	if w.Header().Get("Access-Control-Allow-Origin") != "https://spm.example" {
		t.Errorf("https://<host> not echoed: %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "X-Requested-With") {
		t.Errorf("preflight does not allow the CSRF header: %q", w.Header().Get("Access-Control-Allow-Headers"))
	}
}
