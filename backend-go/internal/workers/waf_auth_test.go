package workers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The WAF management API checks INTERNAL_ALERT_TOKEN: the shipped compose does
// not give the WAF the admin credential. The backend used to send Basic with
// the WAF service credentials (the admin credential by default) on every call,
// so the WAF refused every one of them.
func TestWAFAuthSendsTheServiceTokenWhenSet(t *testing.T) {
	r := httptest.NewRequest("GET", "http://waf:8080/stats", nil)
	WAFAuth{Token: "svc-token", User: "admin", Pass: "pw"}.Apply(r)
	if got := r.Header.Get("Authorization"); got != "Bearer svc-token" {
		t.Errorf("Authorization = %q, want the bearer service token", got)
	}

	r = httptest.NewRequest("GET", "http://waf:8080/stats", nil)
	WAFAuth{User: "admin", Pass: "pw"}.Apply(r)
	if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
		t.Errorf("without a token the service credentials must be sent as Basic, got %q", r.Header.Get("Authorization"))
	}
}

func TestReconcilerPushesWithTheServiceToken(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES('waf_h_entropy','true')")

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/heuristics/toggle" {
			got = r.Header.Get("Authorization")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	if out := reconcileWAF(context.Background(), db, srv.URL, WAFAuth{Token: "svc-token", User: "u", Pass: "p"}, true); out != reconcileOK {
		t.Fatalf("reconcile outcome %s", out)
	}
	if got != "Bearer svc-token" {
		t.Errorf("the reconciler pushed with Authorization %q, want the bearer service token", got)
	}
}
