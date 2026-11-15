package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// The refusals the middleware answers before any handler runs carry the same
// shape as the handlers' errors: JSON, with status, a code from ErrorCodes and
// a detail. The rate limit used to send its JSON as text/plain.
func TestMiddlewareRefusalsCarryACode(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "spm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AdminUsername: "admin", SecretKey: "k", MaxAttempts: 5, RateLimitWindow: time.Minute}
	svc := auth.NewService(cfg, db)
	read, _, err := database.CreateAPIToken(db, "r", database.ScopeRead, "admin", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})

	router := chi.NewRouter()
	router.With(Auth(svc)).Post("/api/ip-blacklist", ok)
	limited := GlobalRateLimit(0.001, 1)(ok)
	csrf := SessionCSRF(cfg)(ok)
	service := ServiceAuth("s3rv1ce", nil)(ok)

	cases := []struct {
		name string
		h    http.Handler
		req  func() *http.Request
		code int
		want string
	}{
		{"no credential", router, func() *http.Request { return httptest.NewRequest("POST", "/api/ip-blacklist", nil) }, 401, "unauthorized"},
		{"a read token writing", router, func() *http.Request {
			r := httptest.NewRequest("POST", "/api/ip-blacklist", nil)
			r.Header.Set("Authorization", "Bearer "+read)
			return r
		}, 403, "token_scope"},
		{"a cookie request from another site", csrf, func() *http.Request {
			r := httptest.NewRequest("POST", "/api/ip-blacklist", nil)
			r.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "x"})
			return r
		}, 403, "forbidden"},
		{"a wrong service credential", service, func() *http.Request {
			r := httptest.NewRequest("POST", "/api/internal/alert", nil)
			r.Header.Set("Authorization", "Bearer wrong")
			return r
		}, 401, "unauthorized"},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		c.h.ServeHTTP(w, c.req())
		checkError(t, c.name, w, c.code, c.want)
	}
	// The first request takes the bucket's one token; the second is refused.
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/status", nil)
		r.RemoteAddr = "203.0.113.9:4000"
		limited.ServeHTTP(w, r)
		if i == 1 {
			checkError(t, "over the rate limit", w, 429, "rate_limited")
		}
	}
}

func checkError(t *testing.T, name string, w *httptest.ResponseRecorder, code int, want string) {
	t.Helper()
	var body map[string]string
	if w.Code != code {
		t.Errorf("%s: %d, want %d", name, w.Code, code)
		return
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("%s: Content-Type %q, want application/json", name, ct)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["status"] != "error" || body["code"] != want || body["detail"] == "" {
		t.Errorf("%s: body %s, want status error, code %s and a detail", name, w.Body.String(), want)
	}
	known := false
	for _, c := range ErrorCodes {
		known = known || c == body["code"]
	}
	if !known {
		t.Errorf("%s: code %q is not in ErrorCodes", name, body["code"])
	}
}

// Every code ErrorCode gives is one the schema lists.
func TestErrorCodeGivesOnlyListedCodes(t *testing.T) {
	listed := map[string]bool{}
	for _, c := range ErrorCodes {
		listed[c] = true
	}
	for status := 400; status < 600; status++ {
		if c := ErrorCode(status); !listed[c] {
			t.Errorf("ErrorCode(%d) = %q, not in ErrorCodes", status, c)
		}
	}
}
