package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
	"github.com/go-chi/chi/v5"
)

func TestSecurityHandlers_ReceiveAlert(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()

	notify := NewNotifyQueue(t.Context(), db, "0000000000000000000000000000000000000000000000000000000000000000")
	h := NewSecurityHandlers(db, nil, nil, notify)

	alert := models.InternalAlert{
		EventType: "test_event",
		Message:   "test message",
		Level:     "info",
		Details:   map[string]any{"foo": "bar"},
	}
	body, _ := json.Marshal(alert)
	r := httptest.NewRequest("POST", "/api/internal/alert", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.ReceiveAlert(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	// Note: We don't wait for the notification worker to finish in this simple test
}

func TestSecurityHandlers_GetRateLimits(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSecurityHandlers(db, svc, cfg, nil)

	r := httptest.NewRequest("GET", "/api/security/rate-limits", nil)
	w := httptest.NewRecorder()
	h.GetRateLimits(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestSecurityHandlers_ClearRateLimit(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSecurityHandlers(db, svc, cfg, nil)

	_, _, _ = svc.Authenticate(httptest.NewRequest("GET", "/", nil)) // adds an attempt? no, fails because no auth

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("ip", "1.1.1.1")
	r := httptest.NewRequest("DELETE", "/api/security/rate-limits/1.1.1.1", nil)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()

	// Should be 404 because no active rate limit for 1.1.1.1
	h.ClearRateLimit(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestSecurityHandlers_Score(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSecurityHandlers(db, nil, nil, nil)

	// Set some settings
	_, _ = db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES ('enable_waf', 'true')")
	_, _ = db.Exec("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES ('enable_ip_blacklist', 'true')")

	r := httptest.NewRequest("GET", "/api/security/score", nil)
	w := httptest.NewRecorder()
	h.Score(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	data := resp["data"].(map[string]any)
	score := data["score"].(float64)
	if score < 40 { // 25 (WAF) + 15 (IP Blacklist) = 40
		t.Errorf("Expected score at least 40, got %f", score)
	}
}

func TestSecurityHandlers_CVECheck(t *testing.T) {
	h := &SecurityHandlers{}
	r := httptest.NewRequest("GET", "/api/security/cve", nil)
	w := httptest.NewRecorder()
	h.CVECheck(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

// SECURE-AUTH-02. The WAF used to authenticate to /api/internal/alert with
// BASIC_AUTH_USERNAME/PASSWORD, so the container that parses
// attacker-controlled request bodies held a credential that opens every
// administrative endpoint. The route now takes a dedicated token.
//
// This goes through Register and a real chi router rather than calling
// ReceiveAlert directly: the defect being fixed is in the WIRING, and a test
// that calls the handler passes either way.
func TestReceiveAlert_RequiresServiceToken(t *testing.T) {
	// authMW that accepts everything — it stands in for a valid admin session.
	// If admin auth still reached ReceiveAlert, the unauthenticated cases below
	// would return 200 and the finding would be open.
	acceptAll := func(next http.Handler) http.Handler { return next }

	post := func(t *testing.T, token, header string) int {
		t.Helper()
		db, svc, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		cfg.AlertToken = token
		r := chi.NewRouter()
		NewSecurityHandlers(db, svc, cfg, NewNotifyQueue(t.Context(), db, "0000000000000000000000000000000000000000000000000000000000000000")).Register(r, acceptAll)

		body, _ := json.Marshal(models.InternalAlert{EventType: "waf_block", Message: "blocked by rule 42", Level: "warning"})
		req := httptest.NewRequest("POST", "/api/internal/alert", bytes.NewReader(body))
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	if code := post(t, "s3rv1ce-t0ken", "Bearer s3rv1ce-t0ken"); code != http.StatusOK {
		t.Errorf("the WAF's own token was rejected: got %d, want 200", code)
	}
	if code := post(t, "s3rv1ce-t0ken", ""); code != http.StatusUnauthorized {
		t.Errorf("an admin session reached the internal alert route: got %d, want 401", code)
	}
	if code := post(t, "s3rv1ce-t0ken", "Bearer wrong-token"); code != http.StatusUnauthorized {
		t.Errorf("a wrong token was accepted: got %d, want 401", code)
	}
	// A prefix of the real token must not pass — the length check has to run
	// before the constant-time compare, which returns 0 for unequal lengths.
	if code := post(t, "s3rv1ce-t0ken", "Bearer s3rv1ce"); code != http.StatusUnauthorized {
		t.Errorf("a token prefix was accepted: got %d, want 401", code)
	}

	// Fallback: with no token configured the route keeps accepting admin auth,
	// so an in-place upgrade does not silently stop delivering alerts.
	if code := post(t, "", ""); code != http.StatusOK {
		t.Errorf("with no token configured the admin fallback must still work: got %d, want 200", code)
	}
}

// SECURE-CONC-01 / SECURE-OBS-01. The notification worker was spawned with no
// owner: nothing cancelled it, the channel was never closed, and it was not
// covered by the shutdown drain — so queued security alerts were discarded at
// exit. It also emitted no liveness signal, and because zero notifications is
// the healthy state for a quiet system, it could stop with no observable
// difference.
func TestNotifyQueueIsOwnedAndReportsLiveness(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()

	// The worker must register itself with the shutdown drain, so Wait() blocks
	// until it returns and unblocks once the context is cancelled. If it were
	// untracked, Wait() would return immediately whether or not it had stopped.
	ctx, cancel := context.WithCancel(context.Background())
	_ = NewNotifyQueue(ctx, db, "0000000000000000000000000000000000000000000000000000000000000000")

	stopped := make(chan struct{})
	go func() { workers.Wait(); close(stopped) }()

	select {
	case <-stopped:
		t.Fatal("workers.Wait() returned while the notification worker was still running — it is not tracked")
	case <-time.After(150 * time.Millisecond):
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("the notification worker did not stop when its context was cancelled")
	}

	// And it reports liveness, so a stopped worker is distinguishable from an
	// idle one. WorkerHeartbeat is called before the first receive, so the
	// gauge is set even though nothing was ever enqueued.
	if ts := metrics.WorkerHeartbeatSeconds("notify_queue"); ts == 0 {
		t.Error("the notification worker emitted no liveness signal — a stopped queue looks exactly like a quiet one")
	}
}
