package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// How a request reaches the backend. Through the dashboard, nginx sets
// X-Forwarded-For and X-Real-IP to the client's address, replacing what the
// client sent; on the backend's own port neither is set, and the peer is the
// Docker gateway (both measured on Docker with iptables and with a userland
// proxy).
func throughDashboard(req *http.Request) {
	req.RemoteAddr = "172.18.0.5:41000"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.Header.Set("X-Real-IP", "198.51.100.7")
}

func onBackendPort(req *http.Request) { req.RemoteAddr = "172.18.0.1:41000" }

func (e *oidcEnv) send(method, path, body string, via func(*http.Request), set func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	via(req)
	if set != nil {
		set(req)
	}
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

const adminLogin = `{"username":"admin","password":"admin-12345"}`

func passwordOffEnv(t *testing.T) *oidcEnv {
	e := newOIDCEnv(t)
	e.cfg.OIDC.PasswordOff = true
	return e
}

func TestThePasswordIsRefusedThroughTheDashboardOnly(t *testing.T) {
	e := passwordOffEnv(t)

	// Signing in: refused through the dashboard, before the password is
	// checked, so the attempt is not counted either.
	for i := 0; i < 7; i++ {
		w := e.send("POST", "/api/auth/login", `{"username":"admin","password":"wrong"}`, throughDashboard, nil)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "turned off") {
			t.Fatalf("login through the dashboard: %d %s", w.Code, w.Body.String())
		}
	}
	if snap := e.svc.RateLimitSnapshot(); len(snap) != 0 {
		t.Errorf("refused sign-ins were counted: %v", snap)
	}
	// Recorded once for the address, not once per attempt.
	if got := e.audit("login_failed"); len(got) != 1 {
		t.Errorf("audit login_failed %v, want 1", got)
	}
	w := e.send("POST", "/api/auth/login", adminLogin, throughDashboard, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("right password through the dashboard: %d %s", w.Code, w.Body.String())
	}
	// Only X-Real-IP is enough to tell the dashboard.
	w = e.send("POST", "/api/auth/login", adminLogin, onBackendPort, func(r *http.Request) { r.Header.Set("X-Real-IP", "198.51.100.7") })
	if w.Code != http.StatusForbidden {
		t.Fatalf("login with X-Real-IP only: %d", w.Code)
	}

	// On the backend's port: break-glass.
	w = e.send("POST", "/api/auth/login", adminLogin, onBackendPort, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login on the backend port: %d %s", w.Code, w.Body.String())
	}
	var tokens map[string]string
	json.Unmarshal(w.Body.Bytes(), &tokens) //nolint:errcheck
	cw := e.send("POST", "/api/auth/login", adminLogin, onBackendPort, func(r *http.Request) { r.Header.Set("X-SPM-Session", "cookie") })
	cookie := cookieNamed(cw, auth.SessionCookieName)
	if cookie == nil {
		t.Fatalf("cookie login on the backend port: %d", cw.Code)
	}

	// Every way the admin authenticates: refused through the dashboard,
	// accepted on the backend's port.
	for name, set := range map[string]func(*http.Request){
		"basic":  func(r *http.Request) { r.Header.Set("Authorization", basicHeader("admin", "admin-12345")) },
		"bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tokens["access_token"]) },
		"cookie": func(r *http.Request) { r.AddCookie(cookie) },
	} {
		if w := e.send("GET", "/api/settings", "", throughDashboard, set); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "turned off") {
			t.Errorf("%s through the dashboard: %d %s", name, w.Code, w.Body.String())
		}
		if w := e.send("GET", "/api/settings", "", onBackendPort, set); w.Code != http.StatusOK {
			t.Errorf("%s on the backend port: %d %s", name, w.Code, w.Body.String())
		}
	}
	// A wrong password through the dashboard is not checked, so not counted.
	for i := 0; i < 7; i++ {
		w := e.send("GET", "/api/settings", "", throughDashboard, func(r *http.Request) { r.Header.Set("Authorization", basicHeader("admin", "guess")) })
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "turned off") {
			t.Fatalf("wrong Basic through the dashboard: %d %s", w.Code, w.Body.String())
		}
	}
	if snap := e.svc.RateLimitSnapshot(); len(snap) != 0 {
		t.Errorf("Basic through the dashboard was counted: %v", snap)
	}

	refresh := `{"refresh_token":"` + tokens["refresh_token"] + `"}`
	if w := e.send("POST", "/api/auth/refresh", refresh, throughDashboard, nil); w.Code != http.StatusForbidden {
		t.Errorf("refresh through the dashboard: %d %s", w.Code, w.Body.String())
	}
	if w := e.send("POST", "/api/auth/refresh", refresh, onBackendPort, nil); w.Code != http.StatusOK {
		t.Errorf("refresh on the backend port: %d %s", w.Code, w.Body.String())
	}
}

func TestProviderSessionsAndTokensStillWorkThroughTheDashboard(t *testing.T) {
	e := passwordOffEnv(t)
	s := e.start()
	e.idp.issue("c1", s.challenge, e.idp.idClaims(s.nonce, "alice@example.com"))
	session := cookieNamed(e.finish(s, "c1"), auth.SessionCookieName)
	if session == nil {
		t.Fatal("no OIDC session")
	}
	if w := e.send("GET", "/api/settings", "", throughDashboard, func(r *http.Request) { r.AddCookie(session) }); w.Code != http.StatusOK {
		t.Errorf("OIDC session through the dashboard: %d %s", w.Code, w.Body.String())
	}

	plain, _, err := database.CreateAPIToken(e.db, "grafana", database.ScopeRead, "admin", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if w := e.send("GET", "/api/settings", "", throughDashboard, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+plain) }); w.Code != http.StatusOK {
		t.Errorf("API token through the dashboard: %d %s", w.Code, w.Body.String())
	}
}

func TestTheSignInPageIsToldWhetherToOfferThePassword(t *testing.T) {
	e := passwordOffEnv(t)
	status := func(via func(*http.Request)) map[string]any {
		var got struct{ Data map[string]any }
		json.Unmarshal(e.send("GET", "/api/auth/oidc", "", via, nil).Body.Bytes(), &got) //nolint:errcheck
		return got.Data
	}
	if got := status(throughDashboard); got["password_login"] != false {
		t.Errorf("through the dashboard: %v", got)
	}
	if got := status(onBackendPort); got["password_login"] != true {
		t.Errorf("on the backend port: %v", got)
	}
}

func TestThePasswordStaysOnUnlessTurnedOff(t *testing.T) {
	e := newOIDCEnv(t)
	if w := e.send("POST", "/api/auth/login", adminLogin, throughDashboard, nil); w.Code != http.StatusOK {
		t.Fatalf("login through the dashboard: %d %s", w.Code, w.Body.String())
	}
	if w := e.send("GET", "/api/settings", "", throughDashboard, func(r *http.Request) { r.Header.Set("Authorization", basicHeader("admin", "admin-12345")) }); w.Code != http.StatusOK {
		t.Errorf("basic through the dashboard: %d", w.Code)
	}
}
