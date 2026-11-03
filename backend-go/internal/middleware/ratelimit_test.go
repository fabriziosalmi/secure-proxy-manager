package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The WAF's own calls, with the service token, do not spend the per-IP
// bucket: a burst of signals must not leave a block alert a 429. Anyone
// else from that address, or the token on another route, still does.
func TestGlobalRateLimitLetsTheWAFsServiceCallsThrough(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := GlobalRateLimit(1, 2, InternalServiceRequest("s3rv1ce"))(ok)
	send := func(path, token string) int {
		r := httptest.NewRequest("POST", path, nil)
		r.RemoteAddr = "203.0.113.5:4000"
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 10; i++ {
		if code := send("/api/internal/signals", "s3rv1ce"); code != http.StatusOK {
			t.Fatalf("service call %d: %d, want 200", i, code)
		}
	}
	// The bucket (burst 2) is still full for everyone else.
	if send("/api/internal/alert", "") != http.StatusOK || send("/api/internal/alert", "wrong") != http.StatusOK {
		t.Fatal("the service calls spent the bucket")
	}
	if code := send("/api/internal/alert", "wrong"); code != http.StatusTooManyRequests {
		t.Errorf("a wrong token was exempt: %d", code)
	}
	if code := send("/api/settings", "s3rv1ce"); code != http.StatusTooManyRequests {
		t.Errorf("the token on another route was exempt: %d", code)
	}
	if code := send("/api/internal/alert", "s3rv1ce"); code != http.StatusOK {
		t.Errorf("the token on the alert route: %d, want 200", code)
	}

	// No token configured: nothing is exempt.
	h = GlobalRateLimit(1, 1, InternalServiceRequest(""))(ok)
	send("/api/internal/signals", "")
	if code := send("/api/internal/signals", ""); code != http.StatusTooManyRequests {
		t.Errorf("with no token configured: %d, want 429", code)
	}
}
