package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// The Metrics middleware must record a request under its matched chi route
// pattern (not the raw path), and the recorded series must show up on /metrics.
func TestMetricsMiddlewareRecordsRoutePattern(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Metrics)
	r.Get("/api/things/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	req := httptest.NewRequest("GET", "/api/things/42", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	// Scrape /metrics and confirm the templated route (not /api/things/42) and
	// the 418 status are present.
	mw := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(mw, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(mw.Result().Body)
	out := string(body)

	if !strings.Contains(out, `spm_http_requests_total`) {
		t.Fatal("spm_http_requests_total not exposed on /metrics")
	}
	if !strings.Contains(out, `route="/api/things/{id}"`) {
		t.Errorf("expected templated route label, got:\n%s", grepLines(out, "spm_http_requests_total"))
	}
	if !strings.Contains(out, `status="418"`) {
		t.Errorf("expected status=418 label, got:\n%s", grepLines(out, "spm_http_requests_total"))
	}
}

// AccessLog must not break a normal handler and must skip health/scrape paths.
func TestAccessLogPassesThrough(t *testing.T) {
	h := AccessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	for _, path := range []string{"/api/foo", "/metrics", "/readyz"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", path, w.Code)
		}
		if w.Body.String() != "ok" {
			t.Errorf("%s: body not passed through", path)
		}
	}
}

func grepLines(s, sub string) string {
	var b strings.Builder
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, sub) {
			b.WriteString(ln)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// The method label was the raw request method, so every invented method
// (AUDITPROBEA, AUDITPROBEB, ...) created a counter series and a 12-bucket
// histogram series that were never freed. Metrics runs before the rate limiter
// and needs no authentication, so a remote client could grow backend memory
// without bound; nginx forwards any all-letters method.
func TestMetricsMethodLabelIsBounded(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Metrics)
	r.Get("/api/health-probe", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	for i := 0; i < 500; i++ {
		m := "CARDPROBE" + string(rune('A'+i%26)) + string(rune('A'+(i/26)%26))
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(m, "/api/health-probe", nil))
	}
	mw := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(mw, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(mw.Result().Body)
	if strings.Contains(string(body), `method="CARDPROBE`) {
		t.Errorf("client-chosen methods became label values:\n%s", grepLines(string(body), "CARDPROBE")[:300])
	}
	if !strings.Contains(string(body), `method="OTHER"`) {
		t.Error("unknown methods are not folded into OTHER")
	}
}
