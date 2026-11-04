package middleware

import (
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

// A subtree that applies Auth with Use, as the runtime profiles do, is held
// to the token rule too: the middleware runs before the subtree routes, and
// the pattern it sees then (/debug/pprof/*) is what the rule refuses.
func TestATokenDoesNotReachASubtreeMountedWithUse(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "spm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(&config.Config{AdminUsername: "admin", SecretKey: "k", MaxAttempts: 5, RateLimitWindow: time.Minute}, db)
	write, _, err := database.CreateAPIToken(db, "w", database.ScopeWrite, "admin", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Route("/debug/pprof", func(pr chi.Router) {
		pr.Use(Auth(svc))
		pr.Get("/heap", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	})
	r.With(Auth(svc)).Get("/api/status", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	for path, want := range map[string]int{
		"/debug/pprof/heap": http.StatusForbidden,
		"/api/status":       http.StatusNoContent,
	} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+write)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("write token GET %s: %d, want %d", path, w.Code, want)
		}
	}
}
