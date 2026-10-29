package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func noRetryDelay(t *testing.T) {
	t.Helper()
	prev := notifyRetryDelay
	notifyRetryDelay = func(int) time.Duration { return 0 }
	t.Cleanup(func() { notifyRetryDelay = prev })
}

func failedCount(reason string) int64 { return notifyFailed[reason].Load() }

// A delivery the backend refuses or cannot take is counted by reason. A 4xx is
// a configuration problem (a wrong token) and is not retried; a 5xx or a
// network error is retried, then counted once. Before, all of these were one
// log line and no metric, so waf_notify_dropped_total stayed 0 while every
// alert was lost.
func TestFailedAlertDeliveriesAreCountedAndRetriedByReason(t *testing.T) {
	noRetryDelay(t)
	t.Setenv("INTERNAL_ALERT_TOKEN", "t0ken")
	cases := []struct {
		name, reason string
		status       int
		wantCalls    int32
	}{
		{"rejected token", "rejected", 401, 1},
		{"server error", "server_error", 503, int32(notifyAttempts)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(c.status)
			}))
			defer srv.Close()
			t.Setenv("BACKEND_URL", srv.URL)
			before := failedCount(c.reason)
			notifyBackend(map[string]interface{}{"event_type": "waf_block", "details": map[string]interface{}{"event_id": "e1"}})
			if got := calls.Load(); got != c.wantCalls {
				t.Errorf("backend called %d times, want %d", got, c.wantCalls)
			}
			if got := failedCount(c.reason) - before; got != 1 {
				t.Errorf("waf_notify_failed_total{reason=%q} rose by %d, want 1", c.reason, got)
			}
		})
	}

	t.Run("network error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close() // nothing listens there now
		t.Setenv("BACKEND_URL", url)
		before := failedCount("network")
		notifyBackend(map[string]interface{}{"event_type": "waf_block"})
		if got := failedCount("network") - before; got != 1 {
			t.Errorf("waf_notify_failed_total{reason=\"network\"} rose by %d, want 1", got)
		}
	})

	t.Run("a 5xx that recovers is delivered and not counted", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if calls.Add(1) == 1 {
				w.WriteHeader(503)
				return
			}
			w.WriteHeader(200)
		}))
		defer srv.Close()
		t.Setenv("BACKEND_URL", srv.URL)
		before := failedCount("server_error")
		notifyBackend(map[string]interface{}{"event_type": "waf_block"})
		if calls.Load() != 2 || failedCount("server_error") != before {
			t.Errorf("calls %d, server_error +%d; want 2 calls and no failure counted", calls.Load(), failedCount("server_error")-before)
		}
	})

	t.Run("no credential", func(t *testing.T) {
		t.Setenv("INTERNAL_ALERT_TOKEN", "")
		t.Setenv("BASIC_AUTH_USERNAME", "")
		t.Setenv("BASIC_AUTH_PASSWORD", "")
		before := failedCount("no_credential")
		notifyBackend(map[string]interface{}{"event_type": "waf_block"})
		if got := failedCount("no_credential") - before; got != 1 {
			t.Errorf("waf_notify_failed_total{reason=\"no_credential\"} rose by %d, want 1", got)
		}
	})
}

// /metrics exposes the failures with their reason.
func TestMetricsExposeAlertDeliveryFailures(t *testing.T) {
	w := httptest.NewRecorder()
	(&MgmtHandlers{}).MetricsHandler(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, reason := range []string{"network", "rejected", "server_error", "no_credential"} {
		if !strings.Contains(w.Body.String(), `waf_notify_failed_total{reason="`+reason+`"}`) {
			t.Errorf("metrics lack waf_notify_failed_total{reason=%q}", reason)
		}
	}
}

// On shutdown the queued alerts are delivered before the process exits; the
// WAF used to exit on SIGTERM with up to 64 of them still queued.
func TestShutdownDeliversQueuedAlerts(t *testing.T) {
	noRetryDelay(t)
	drainNotifications()
	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		got.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	t.Setenv("BACKEND_URL", srv.URL)
	t.Setenv("INTERNAL_ALERT_TOKEN", "t0ken")

	for i := 0; i < 5; i++ {
		notifyBlock("e", "192.168.1.1", "http://x.test/", "URL", 10, []string{"SQL_INJECTION"}, []string{"SQL-001"})
	}
	stop := make(chan struct{})
	go notifyWorker(stop)
	defer close(stop)

	if !drainPendingAlerts(2 * time.Second) {
		t.Fatalf("pending alerts not drained: %d left", notifyPending.Load())
	}
	if got.Load() != 5 {
		t.Errorf("backend received %d alerts, want 5", got.Load())
	}
}

// The drain gives up at its deadline instead of holding shutdown forever.
func TestShutdownDrainHasADeadline(t *testing.T) {
	drainNotifications()
	notifyPending.Add(1)
	defer notifyPending.Add(-1)
	start := time.Now()
	if drainPendingAlerts(100 * time.Millisecond) {
		t.Error("drain reported success with an alert still pending")
	}
	if time.Since(start) > time.Second {
		t.Errorf("drain took %v, want about its 100ms deadline", time.Since(start))
	}
}
