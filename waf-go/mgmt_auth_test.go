package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// SECURE-SEC-02. The management credential guards /categories/toggle, the route
// that can switch off SQL-injection inspection on a live proxy. It is now
// compared with crypto/subtle, and both fields are compared unconditionally so
// the total time does not reveal which one failed.
//
// This pins the behaviour, not the timing: a unit test cannot demonstrate
// constant-timeness, and claiming otherwise would be worse than not testing it.
func TestMgmtAuthMiddleware(t *testing.T) {
	t.Setenv("BASIC_AUTH_USERNAME", "adminuser")
	t.Setenv("BASIC_AUTH_PASSWORD", "correct-horse-battery")

	call := func(user, pass string, withAuth bool) int {
		h := mgmtAuthMiddleware(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		r := httptest.NewRequest("GET", "/categories", nil)
		if withAuth {
			r.SetBasicAuth(user, pass)
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}

	if got := call("adminuser", "correct-horse-battery", true); got != http.StatusOK {
		t.Errorf("correct credentials rejected: %d", got)
	}
	for _, c := range []struct {
		name, user, pass string
	}{
		{"wrong password", "adminuser", "wrong"},
		{"wrong username", "wronguser", "correct-horse-battery"},
		{"both wrong", "wronguser", "wrong"},
		{"password is a prefix", "adminuser", "correct-horse"},
		{"username is a prefix", "adminus", "correct-horse-battery"},
		{"empty", "", ""},
	} {
		if got := call(c.user, c.pass, true); got != http.StatusUnauthorized {
			t.Errorf("%s was accepted: %d", c.name, got)
		}
	}
	if got := call("", "", false); got != http.StatusUnauthorized {
		t.Errorf("no Authorization header was accepted: %d", got)
	}

	// With no credentials configured the endpoint denies rather than opening.
	t.Setenv("BASIC_AUTH_USERNAME", "")
	t.Setenv("BASIC_AUTH_PASSWORD", "")
	if got := call("adminuser", "correct-horse-battery", true); got != http.StatusForbidden {
		t.Errorf("unconfigured management auth did not fail closed: %d", got)
	}
}

// The shipped compose gives the WAF INTERNAL_ALERT_TOKEN and not the admin
// credential (SECURE-AUTH-02), but the middleware read only BASIC_AUTH_*, so on
// every real deployment it answered 403 "not configured" to the backend: WAF
// stats, category and heuristic toggles, reset and the reconciler all failed,
// and the dashboard hid its WAF cards. The service token is the credential now.
func TestMgmtAuthAcceptsTheServiceToken(t *testing.T) {
	t.Setenv("BASIC_AUTH_USERNAME", "")
	t.Setenv("BASIC_AUTH_PASSWORD", "")
	t.Setenv("INTERNAL_ALERT_TOKEN", "svc-token-0123456789")

	call := func(set func(*http.Request)) int {
		h := mgmtAuthMiddleware(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		r := httptest.NewRequest("GET", "/categories", nil)
		set(r)
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}
	if got := call(func(r *http.Request) { r.Header.Set("Authorization", "Bearer svc-token-0123456789") }); got != http.StatusOK {
		t.Errorf("the service token was rejected: %d", got)
	}
	for name, set := range map[string]func(*http.Request){
		"wrong token":     func(r *http.Request) { r.Header.Set("Authorization", "Bearer svc-token-9999999999") },
		"token prefix":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer svc-token") },
		"no header":       func(*http.Request) {},
		"token as basic":  func(r *http.Request) { r.SetBasicAuth("svc", "svc-token-0123456789") },
		"empty bearer":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"lowercase basic": func(r *http.Request) { r.Header.Set("Authorization", "basic Og==") },
	} {
		if got := call(set); got != http.StatusUnauthorized {
			t.Errorf("%s: got %d, want 401", name, got)
		}
	}
}
