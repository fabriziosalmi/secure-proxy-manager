package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

// mockProvider is an OpenID Connect provider as far as SPM uses one:
// discovery, keys and the token endpoint, which checks the PKCE verifier and
// accepts each code once, as a real provider does.
type mockProvider struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu    sync.Mutex
	codes map[string]mockCode
}

type mockCode struct {
	challenge string
	claims    jwt.MapClaims
}

func newMockProvider(t *testing.T) *mockProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockProvider{key: key, codes: map[string]mockCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"issuer":                                m.srv.URL,
			"authorization_endpoint":                m.srv.URL + "/authorize",
			"token_endpoint":                        m.srv.URL + "/token",
			"jwks_uri":                              m.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"end_session_endpoint":                  m.srv.URL + "/logout",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{ //nolint:errcheck
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		m.mu.Lock()
		c, ok := m.codes[r.Form.Get("code")]
		delete(m.codes, r.Form.Get("code")) // a code is used once
		m.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant"}`)) //nolint:errcheck
			return
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c.claims)
		tok.Header["kid"] = "k1"
		id, _ := tok.SignedString(key)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": id}) //nolint:errcheck
	})
	m.srv = httptest.NewTLSServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

// idClaims is a valid ID token for the sign-in started with nonce.
func (m *mockProvider) idClaims(nonce, email string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": m.srv.URL, "sub": "u-" + email, "aud": "spm",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		"nonce": nonce, "email": email, "email_verified": true,
	}
}

// issue registers a code the provider will exchange for claims, bound to
// the PKCE challenge the sign-in sent.
func (m *mockProvider) issue(code, challenge string, claims jwt.MapClaims) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[code] = mockCode{challenge: challenge, claims: claims}
}

type oidcEnv struct {
	t   *testing.T
	db  *sql.DB
	svc *auth.Service
	h   *AuthHandlers
	cfg *config.Config
	r   chi.Router
	idp *mockProvider
}

func newOIDCEnv(t *testing.T) *oidcEnv {
	db, svc, cfg, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	idp := newMockProvider(t)
	cfg.OIDC = config.OIDC{
		Issuer: idp.srv.URL, ClientID: "spm", ClientSecret: "client-secret",
		RedirectURL: "https://spm.test/api/auth/oidc/callback", Scopes: []string{"openid", "email"},
		AllowedEmails: []string{"alice@example.com"}, AllowedGroups: []string{"spm-admins"},
		GroupsClaim: "groups", Session: time.Hour, Label: "Example ID",
	}
	r := chi.NewRouter()
	h := NewAuthHandlers(authStore(db), svc, cfg, nil, nil).WithOIDCHTTPClient(idp.srv.Client())
	h.Register(r)
	r.With(middleware.Auth(svc)).Get("/api/settings", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return &oidcEnv{t: t, db: db, svc: svc, h: h, cfg: cfg, r: r, idp: idp}
}

func (e *oidcEnv) get(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// start is the browser beginning a sign-in: the redirect to the provider's
// authorize URL, and the flow cookie.
type started struct {
	state, nonce, challenge string
	flow                    *http.Cookie
}

func (e *oidcEnv) start() started {
	e.t.Helper()
	w := e.get("/api/auth/oidc/login")
	if w.Code != http.StatusFound {
		e.t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(u.String(), e.idp.srv.URL+"/authorize") {
		e.t.Fatalf("login redirects to %q", w.Header().Get("Location"))
	}
	q := u.Query()
	for k, want := range map[string]string{"client_id": "spm", "response_type": "code", "code_challenge_method": "S256", "redirect_uri": "https://spm.test/api/auth/oidc/callback"} {
		if q.Get(k) != want {
			e.t.Errorf("authorize %s=%q, want %q", k, q.Get(k), want)
		}
	}
	flow := cookieNamed(w, oidcFlowCookie)
	if flow == nil || !flow.HttpOnly || !flow.Secure || flow.SameSite != http.SameSiteLaxMode {
		e.t.Fatalf("flow cookie %+v", flow)
	}
	return started{state: q.Get("state"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), flow: flow}
}

// finish is the provider sending the browser back with code.
func (e *oidcEnv) finish(s started, code string) *httptest.ResponseRecorder {
	return e.get("/api/auth/oidc/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(s.state), s.flow)
}

func (e *oidcEnv) audit(action string) []string {
	rows, err := e.db.Query(`SELECT username FROM audit_log WHERE action = ? ORDER BY id`, action)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		rows.Scan(&u) //nolint:errcheck
		out = append(out, u)
	}
	return out
}

func TestOIDCLetsAnAllowedPersonIn(t *testing.T) {
	e := newOIDCEnv(t)
	s := e.start()
	e.idp.issue("c1", s.challenge, e.idp.idClaims(s.nonce, "Alice@Example.com"))
	w := e.finish(s, "c1")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/" {
		t.Fatalf("callback: %d to %q", w.Code, w.Header().Get("Location"))
	}
	session := cookieNamed(w, auth.SessionCookieName)
	if session == nil || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie %+v", session)
	}
	if until := time.Until(session.Expires); until < 59*time.Minute || until > time.Hour+time.Second {
		t.Errorf("session lasts %v, want 1h", until)
	}
	if c := cookieNamed(w, oidcFlowCookie); c == nil || c.MaxAge >= 0 {
		t.Errorf("the flow cookie is not cleared: %+v", c)
	}

	var got struct {
		Data struct{ Username, Via string } `json:"data"`
	}
	sw := e.get("/api/session", session)
	json.Unmarshal(sw.Body.Bytes(), &got) //nolint:errcheck
	if sw.Code != http.StatusOK || got.Data.Username != "oidc:alice@example.com" || got.Data.Via != "cookie" {
		t.Fatalf("session: %d %s", sw.Code, sw.Body.String())
	}
	if logins := e.audit("login"); len(logins) != 1 || logins[0] != "oidc:alice@example.com" {
		t.Errorf("audit login %v", logins)
	}

	// The same callback again: the flow cookie was cleared, and a copy of it
	// meets a code the provider will not exchange twice.
	if w := e.finish(s, "c1"); w.Header().Get("Location") != "/?oidc_error=exchange" || cookieNamed(w, auth.SessionCookieName) != nil {
		t.Errorf("replayed callback: %d to %q", w.Code, w.Header().Get("Location"))
	}
}

func TestOIDCLetsInAMemberOfAnAllowedGroup(t *testing.T) {
	e := newOIDCEnv(t)
	s := e.start()
	c := e.idp.idClaims(s.nonce, "bob@example.com")
	c["groups"] = []string{"staff", "spm-admins"}
	e.idp.issue("c1", s.challenge, c)
	if w := e.finish(s, "c1"); w.Header().Get("Location") != "/" || cookieNamed(w, auth.SessionCookieName) == nil {
		t.Fatalf("group member: %d to %q", w.Code, w.Header().Get("Location"))
	}
}

// Each way a callback can be wrong ends at the dashboard with a reason, with
// no session, and in the audit log.
func TestOIDCRefusesWhatItShould(t *testing.T) {
	for _, c := range []struct {
		name, reason string
		tamper       func(e *oidcEnv, s *started, claims jwt.MapClaims) string // returns the code to send
	}{
		{"a person nobody allowed", "not_allowed", func(_ *oidcEnv, _ *started, cl jwt.MapClaims) string {
			cl["email"], cl["groups"] = "mallory@example.com", []string{"staff"}
			return "c1"
		}},
		{"an unverified email", "unverified_email", func(_ *oidcEnv, _ *started, cl jwt.MapClaims) string {
			cl["email_verified"] = false
			return "c1"
		}},
		{"no email", "no_email", func(_ *oidcEnv, _ *started, cl jwt.MapClaims) string { delete(cl, "email"); return "c1" }},
		{"a wrong state", "state", func(_ *oidcEnv, s *started, _ jwt.MapClaims) string { s.state = "forged"; return "c1" }},
		{"no flow cookie", "state", func(_ *oidcEnv, s *started, _ jwt.MapClaims) string { s.flow = &http.Cookie{Name: "x"}; return "c1" }},
		{"a forged flow cookie", "state", func(_ *oidcEnv, s *started, _ jwt.MapClaims) string {
			payload, _, _ := strings.Cut(s.flow.Value, ".")
			s.flow = &http.Cookie{Name: oidcFlowCookie, Value: payload + ".forged"}
			return "c1"
		}},
		{"an expired flow", "state", func(e *oidcEnv, s *started, _ jwt.MapClaims) string {
			// The real flow, signed as the backend signs it, only past its
			// expiry: everything else would let the sign-in through.
			payload, _, _ := strings.Cut(s.flow.Value, ".")
			raw, _ := base64.RawURLEncoding.DecodeString(payload)
			var f oidcFlow
			json.Unmarshal(raw, &f) //nolint:errcheck
			f.Expires = time.Now().Add(-time.Second).Unix()
			raw, _ = json.Marshal(f)
			payload = base64.RawURLEncoding.EncodeToString(raw)
			s.flow = &http.Cookie{Name: oidcFlowCookie, Value: payload + "." + e.h.flowMAC(payload)}
			return "c1"
		}},
		{"a wrong nonce", "token", func(_ *oidcEnv, _ *started, cl jwt.MapClaims) string { cl["nonce"] = "other"; return "c1" }},
		{"a token for another client", "token", func(_ *oidcEnv, _ *started, cl jwt.MapClaims) string { cl["aud"] = "other-app"; return "c1" }},
		{"an expired token", "token", func(_ *oidcEnv, _ *started, cl jwt.MapClaims) string {
			cl["exp"] = time.Now().Add(-time.Hour).Unix()
			return "c1"
		}},
		{"a token from another issuer", "token", func(_ *oidcEnv, _ *started, cl jwt.MapClaims) string { cl["iss"] = "https://evil.example"; return "c1" }},
		{"a code bound to another verifier", "exchange", func(e *oidcEnv, s *started, cl jwt.MapClaims) string {
			e.idp.issue("c2", "another-challenge", cl)
			return "c2"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newOIDCEnv(t)
			s := e.start()
			claims := e.idp.idClaims(s.nonce, "alice@example.com")
			code := c.tamper(e, &s, claims)
			e.idp.issue("c1", s.challenge, claims)
			w := e.finish(s, code)
			if w.Header().Get("Location") != "/?oidc_error="+c.reason {
				t.Errorf("redirect %q, want reason %s", w.Header().Get("Location"), c.reason)
			}
			if cookieNamed(w, auth.SessionCookieName) != nil {
				t.Error("a session was set")
			}
			if len(e.audit("login_failed")) != 1 || len(e.audit("login")) != 0 {
				t.Errorf("audit: login_failed %v, login %v", e.audit("login_failed"), e.audit("login"))
			}
		})
	}
}

// A session ends when it expires and when the configuration it was issued
// under changes: someone removed from the allow-list is out at once.
func TestAnOIDCSessionEndsWithItsConfiguration(t *testing.T) {
	e := newOIDCEnv(t)
	s := e.start()
	e.idp.issue("c1", s.challenge, e.idp.idClaims(s.nonce, "alice@example.com"))
	session := cookieNamed(e.finish(s, "c1"), auth.SessionCookieName)
	if w := e.get("/api/settings", session); w.Code != http.StatusOK {
		t.Fatalf("fresh session: %d", w.Code)
	}
	e.cfg.OIDC.AllowedEmails = []string{"ops@example.com"}
	if w := e.get("/api/settings", session); w.Code != http.StatusUnauthorized {
		t.Errorf("after the allow-list changed: %d", w.Code)
	}
	e.cfg.OIDC.AllowedEmails = []string{"alice@example.com"}
	if w := e.get("/api/settings", session); w.Code != http.StatusOK {
		t.Errorf("with the configuration restored: %d", w.Code)
	}
	e.cfg.OIDC.Issuer = ""
	if w := e.get("/api/settings", session); w.Code != http.StatusUnauthorized {
		t.Errorf("with OIDC switched off: %d", w.Code)
	}
}

func TestAnExpiredOIDCSessionIsRefused(t *testing.T) {
	e := newOIDCEnv(t)
	e.cfg.OIDC.Session = -time.Minute
	tok, _, err := e.svc.IssueOIDCSession("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if w := e.get("/api/settings", &http.Cookie{Name: auth.SessionCookieName, Value: tok}); w.Code != http.StatusUnauthorized {
		t.Errorf("expired session: %d", w.Code)
	}
}

func TestOIDCIsAbsentWhenNotConfigured(t *testing.T) {
	e := newOIDCEnv(t)
	e.cfg.OIDC = config.OIDC{}
	var st struct {
		Data map[string]any `json:"data"`
	}
	w := e.get("/api/auth/oidc")
	json.Unmarshal(w.Body.Bytes(), &st) //nolint:errcheck
	if st.Data["enabled"] != false || st.Data["label"] != nil {
		t.Errorf("status %s", w.Body.String())
	}
	for _, p := range []string{"/api/auth/oidc/login", "/api/auth/oidc/callback?code=x&state=y"} {
		if w := e.get(p); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}

func TestAPersonSignedInWithOIDCCannotChangeTheLocalPassword(t *testing.T) {
	e := newOIDCEnv(t)
	s := e.start()
	e.idp.issue("c1", s.challenge, e.idp.idClaims(s.nonce, "alice@example.com"))
	session := cookieNamed(e.finish(s, "c1"), auth.SessionCookieName)
	req := httptest.NewRequest("POST", "/api/change-password", strings.NewReader(`{"current_password":"x","new_password":"n3w-passw0rd!"}`))
	req.AddCookie(session)
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("change-password with an OIDC session: %d %s", w.Code, w.Body.String())
	}
}

// Signing out of the dashboard signs out at the provider too: the answer
// names the provider's logout URL, and the session no longer works.
func TestOIDCLogoutEndsTheSessionHereAndAtTheProvider(t *testing.T) {
	e := newOIDCEnv(t)
	s := e.start()
	e.idp.issue("c1", s.challenge, e.idp.idClaims(s.nonce, "alice@example.com"))
	session := cookieNamed(e.finish(s, "c1"), auth.SessionCookieName)

	req := httptest.NewRequest("POST", "/api/logout", nil)
	req.AddCookie(session)
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	var out struct {
		LogoutURL string `json:"logout_url"`
	}
	json.Unmarshal(w.Body.Bytes(), &out) //nolint:errcheck
	want := e.idp.srv.URL + "/logout?client_id=spm&post_logout_redirect_uri=https%3A%2F%2Fspm.test%2F"
	if w.Code != http.StatusOK || out.LogoutURL != want {
		t.Errorf("logout: %d %s\nwant logout_url %s", w.Code, w.Body.String(), want)
	}
	if w := e.get("/api/settings", session); w.Code != http.StatusUnauthorized {
		t.Errorf("session after logout: %d", w.Code)
	}

	// The local admin's logout names no provider.
	req = httptest.NewRequest("POST", "/api/logout", nil)
	req.SetBasicAuth("admin", "admin-12345")
	w = httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "logout_url") {
		t.Errorf("local admin logout: %s", w.Body.String())
	}
}
