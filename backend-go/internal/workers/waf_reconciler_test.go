package workers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// fakeWAF answers /health and records /heuristics/toggle pushes; toggleStatus
// is what the toggle endpoint returns.
type fakeWAF struct {
	srv          *httptest.Server
	toggleStatus atomic.Int32
	mu           sync.Mutex
	pushes       []string
}

func newFakeWAF(t *testing.T) *fakeWAF {
	f := &fakeWAF{}
	f.toggleStatus.Store(200)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(200)
		case "/heuristics/toggle":
			f.mu.Lock()
			f.pushes = append(f.pushes, r.URL.Path)
			f.mu.Unlock()
			w.WriteHeader(int(f.toggleStatus.Load()))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeWAF) pushCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.pushes) }

func TestReconcilePassOutcomes(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES('waf_h_entropy','true'),('waf_h_pii','false')")
	waf := newFakeWAF(t)
	ctx := context.Background()

	if got := reconcileWAF(ctx, db, waf.srv.URL, "u", "p", true); got != reconcileOK || waf.pushCount() != 2 {
		t.Fatalf("healthy WAF: outcome %v, %d pushes; want ok, 2", got, waf.pushCount())
	}
	// Not forced: a matching WAF is not rewritten.
	if got := reconcileWAF(ctx, db, waf.srv.URL, "u", "p", false); got != reconcileOK || waf.pushCount() != 2 {
		t.Fatalf("unforced pass: outcome %v, %d pushes; want ok, still 2", got, waf.pushCount())
	}

	// A WAF that answers but refuses the push (a changed credential) used to be
	// reported as success.
	waf.toggleStatus.Store(401)
	if got := reconcileWAF(ctx, db, waf.srv.URL, "u", "p", true); got != reconcilePushFailed {
		t.Errorf("rejected pushes: outcome %v, want push_failed", got)
	}

	waf.srv.Close()
	if got := reconcileWAF(ctx, db, waf.srv.URL, "u", "p", true); got != reconcileUnreachable {
		t.Errorf("dead WAF: outcome %v, want unreachable", got)
	}
}

// The worker must report that it is alive on every pass, reachable or not, so
// the staleness alert can see it; it must count outcomes; and a failed push
// must be retried on the next pass, not left until the WAF restarts.
func TestReconcilerReportsLivenessAndRetriesAFailedPush(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES('waf_h_entropy','true')")
	waf := newFakeWAF(t)
	waf.toggleStatus.Store(401)

	old := reconcileEvery
	reconcileEvery = 20 * time.Millisecond
	defer func() { reconcileEvery = old }()

	beforeHB := metrics.WorkerHeartbeatSeconds("waf_reconciler")
	beforeFail := metrics.WAFReconcileCount("push_failed")
	beforeOK := metrics.WAFReconcileCount("success")

	ctx, cancel := context.WithCancel(context.Background())
	StartWAFReconciler(ctx, db, waf.srv.URL, "u", "p")

	deadline := time.Now().Add(3 * time.Second)
	for waf.pushCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if waf.pushCount() < 3 {
		t.Fatalf("a failed push was not retried: %d pushes", waf.pushCount())
	}
	if metrics.WAFReconcileCount("push_failed") <= beforeFail {
		t.Error("failed passes were not counted")
	}

	// The credential is fixed; the next pass syncs and the counters say so.
	waf.toggleStatus.Store(200)
	deadline = time.Now().Add(3 * time.Second)
	for metrics.WAFReconcileCount("success") <= beforeOK && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if metrics.WAFReconcileCount("success") <= beforeOK {
		t.Error("the recovery was not counted as a success")
	}
	if metrics.WorkerHeartbeatSeconds("waf_reconciler") <= beforeHB {
		t.Error("the reconciler reported no heartbeat")
	}

	// Once synced it stops pushing.
	settled := waf.pushCount()
	time.Sleep(120 * time.Millisecond)
	if n := waf.pushCount(); n != settled {
		t.Errorf("a synced WAF was still being pushed to: %d -> %d", settled, n)
	}

	cancel()
	done := make(chan struct{})
	go func() { Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reconciler did not stop")
	}
}

func TestHeartbeatIsReportedWhenTheWAFIsUnreachable(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := dead.URL
	dead.Close()

	old := reconcileEvery
	reconcileEvery = 20 * time.Millisecond
	defer func() { reconcileEvery = old }()
	before := metrics.WorkerHeartbeatSeconds("waf_reconciler")
	beforeU := metrics.WAFReconcileCount("unreachable")

	ctx, cancel := context.WithCancel(context.Background())
	StartWAFReconciler(ctx, db, url, "u", "p")
	deadline := time.Now().Add(3 * time.Second)
	for metrics.WAFReconcileCount("unreachable") <= beforeU && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	Wait()
	if metrics.WAFReconcileCount("unreachable") <= beforeU {
		t.Error("an unreachable WAF was not counted")
	}
	if metrics.WorkerHeartbeatSeconds("waf_reconciler") <= before {
		t.Error("no heartbeat while the WAF is unreachable: the staleness alert cannot tell this worker is alive")
	}
}
