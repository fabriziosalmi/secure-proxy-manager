package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// SECURE-AUTH-02. The WAF is the component that parses attacker-controlled
// request bodies, and it was given BASIC_AUTH_USERNAME/PASSWORD — the admin
// credential — to notify the backend of a block. Code execution here therefore
// meant full control of the management API. It now sends a token scoped to
// /api/internal/alert, and must not fall back to the admin credential when
// that token is present.
func TestNotifyBackendUsesScopedToken(t *testing.T) {
	type seen struct {
		authz  string
		user   string
		pass   string
		hadBA  bool
		called bool
	}
	var got seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.called = true
		got.authz = r.Header.Get("Authorization")
		got.user, got.pass, got.hadBA = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Run("token set: bearer only, admin credential unused", func(t *testing.T) {
		got = seen{}
		t.Setenv("BACKEND_URL", srv.URL)
		t.Setenv("INTERNAL_ALERT_TOKEN", "waf-alert-token")
		t.Setenv("BASIC_AUTH_USERNAME", "admin")
		t.Setenv("BASIC_AUTH_PASSWORD", "super-secret-admin-password")

		notifyBackend(map[string]interface{}{"event_type": "waf_block"})

		if !got.called {
			t.Fatal("backend was never called")
		}
		if got.authz != "Bearer waf-alert-token" {
			t.Errorf("Authorization = %q, want the scoped bearer token", got.authz)
		}
		if got.hadBA {
			t.Errorf("the admin credential was sent (%s) even though a scoped token is configured", got.user)
		}
	})

	t.Run("no token: falls back to basic auth for upgrades", func(t *testing.T) {
		got = seen{}
		t.Setenv("BACKEND_URL", srv.URL)
		t.Setenv("INTERNAL_ALERT_TOKEN", "")
		t.Setenv("BASIC_AUTH_USERNAME", "admin")
		t.Setenv("BASIC_AUTH_PASSWORD", "super-secret-admin-password")

		notifyBackend(map[string]interface{}{"event_type": "waf_block"})

		if !got.called {
			t.Fatal("backend was never called on the fallback path")
		}
		if !got.hadBA || got.user != "admin" {
			t.Errorf("expected the basic-auth fallback, got Authorization %q", got.authz)
		}
	})

	t.Run("no credential at all: nothing is sent", func(t *testing.T) {
		got = seen{}
		t.Setenv("BACKEND_URL", srv.URL)
		t.Setenv("INTERNAL_ALERT_TOKEN", "")
		t.Setenv("BASIC_AUTH_USERNAME", "")
		t.Setenv("BASIC_AUTH_PASSWORD", "")

		notifyBackend(map[string]interface{}{"event_type": "waf_block"})

		if got.called {
			t.Error("an alert was posted with no credential")
		}
	})
}
