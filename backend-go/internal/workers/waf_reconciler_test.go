package workers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// fakeWAF answers /health, serves its running heuristics on GET /heuristics
// and records /heuristics/toggle pushes; toggleStatus is what the toggle
// endpoint returns, and an accepted toggle changes the running state, as the
// WAF does. heuristicsStatus is what GET /heuristics answers (200 with the
// state by default).
type fakeWAF struct {
	srv              *httptest.Server
	toggleStatus     atomic.Int32
	heuristicsStatus atomic.Int32
	mu               sync.Mutex
	pushes           []string
	state            map[string]bool
}

// wafComposeDefaults is what a freshly started WAF runs: the WAF_H_* values
// docker-compose.yml gives it.
func wafComposeDefaults() map[string]bool {
	return map[string]bool{
		"waf_h_entropy": true, "waf_h_beaconing": true, "waf_h_pii": true,
		"waf_h_sharding": true, "waf_h_ghosting": true, "waf_h_sequence": false,
	}
}

func newFakeWAF(t *testing.T) *fakeWAF {
	f := &fakeWAF{state: wafComposeDefaults()}
	f.toggleStatus.Store(200)
	f.heuristicsStatus.Store(200)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(200)
		case "/heuristics":
			if st := int(f.heuristicsStatus.Load()); st != 200 {
				w.WriteHeader(st)
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": f.state})
		case "/heuristics/toggle":
			var b struct {
				Heuristic string `json:"heuristic"`
				Enabled   bool   `json:"enabled"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			st := int(f.toggleStatus.Load())
			f.mu.Lock()
			f.pushes = append(f.pushes, b.Heuristic)
			if st == 200 {
				f.state[b.Heuristic] = b.Enabled
			}
			f.mu.Unlock()
			w.WriteHeader(st)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeWAF) pushCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.pushes) }

// pushedSince names the heuristics pushed after the first n pushes, sorted.
func (f *fakeWAF) pushedSince(n int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.pushes[n:]...)
	slices.Sort(out)
	return out
}

// restart puts the WAF back on its compose defaults, as a restart does.
func (f *fakeWAF) restart() { f.mu.Lock(); f.state = wafComposeDefaults(); f.mu.Unlock() }

func TestReconcilePassOutcomes(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	// Two stored heuristics: the seed's six rows go first.
	_, _ = db.Exec("DELETE FROM settings WHERE setting_name LIKE 'waf_h_%'")
	_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES('waf_h_entropy','true'),('waf_h_pii','false')")
	waf := newFakeWAF(t)
	ctx := context.Background()

	if got := reconcileWAF(ctx, db, waf.srv.URL, WAFAuth{User: "u", Pass: "p"}, true); got != reconcileOK || waf.pushCount() != 2 {
		t.Fatalf("healthy WAF: outcome %v, %d pushes; want ok, 2", got, waf.pushCount())
	}
	// Not forced: a matching WAF is not rewritten.
	if got := reconcileWAF(ctx, db, waf.srv.URL, WAFAuth{User: "u", Pass: "p"}, false); got != reconcileOK || waf.pushCount() != 2 {
		t.Fatalf("unforced pass: outcome %v, %d pushes; want ok, still 2", got, waf.pushCount())
	}

	// A WAF that answers but refuses the push (a changed credential) used to be
	// reported as success.
	waf.toggleStatus.Store(401)
	if got := reconcileWAF(ctx, db, waf.srv.URL, WAFAuth{User: "u", Pass: "p"}, true); got != reconcilePushFailed {
		t.Errorf("rejected pushes: outcome %v, want push_failed", got)
	}

	waf.srv.Close()
	if got := reconcileWAF(ctx, db, waf.srv.URL, WAFAuth{User: "u", Pass: "p"}, true); got != reconcileUnreachable {
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
	StartWAFReconciler(ctx, db, waf.srv.URL, WAFAuth{User: "u", Pass: "p"})

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
	StartWAFReconciler(ctx, db, url, WAFAuth{User: "u", Pass: "p"})
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

// A WAF that restarts between two passes comes back on its compose defaults
// and answers /health as before. The reconciler used to push only after it had
// itself seen the WAF unreachable, so the restart went unnoticed and the WAF
// stayed on WAF_H_* while the Settings page showed the stored values. Every
// pass now compares the WAF's running heuristics with the stored ones and
// pushes the ones that differ; a WAF that matches gets no writes, and a WAF
// whose running state cannot be read gets every stored value.
func TestReconcilerPushesWhatAWAFRestartReverted(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	_, _ = db.Exec("DELETE FROM settings WHERE setting_name LIKE 'waf_h_%'")
	_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES('waf_h_sequence','true'),('waf_h_pii','false')")
	waf := newFakeWAF(t)
	ctx := context.Background()
	auth := WAFAuth{Token: "svc-token"}

	if got := reconcileWAF(ctx, db, waf.srv.URL, auth, true); got != reconcileOK || waf.pushCount() != 2 {
		t.Fatalf("first pass: outcome %v, %d pushes; want ok, 2", got, waf.pushCount())
	}
	if got := reconcileWAF(ctx, db, waf.srv.URL, auth, false); got != reconcileOK || waf.pushCount() != 2 {
		t.Fatalf("matching WAF: outcome %v, %d pushes; want ok and no new push", got, waf.pushCount())
	}

	waf.restart()
	before := waf.pushCount()
	if got := reconcileWAF(ctx, db, waf.srv.URL, auth, false); got != reconcileOK {
		t.Fatalf("pass after a restart: outcome %v, want ok", got)
	}
	if pushed := waf.pushedSince(before); !slices.Equal(pushed, []string{"waf_h_pii", "waf_h_sequence"}) {
		t.Fatalf("after a restart the reconciler pushed %v, want [waf_h_pii waf_h_sequence]", pushed)
	}
	waf.mu.Lock()
	seq, pii := waf.state["waf_h_sequence"], waf.state["waf_h_pii"]
	waf.mu.Unlock()
	if !seq || pii {
		t.Errorf("the WAF runs waf_h_sequence=%v waf_h_pii=%v, want true, false as stored", seq, pii)
	}
	if got := reconcileWAF(ctx, db, waf.srv.URL, auth, false); got != reconcileOK || waf.pushCount() != before+2 {
		t.Errorf("matching again: outcome %v, %d pushes; want ok, %d", got, waf.pushCount(), before+2)
	}

	// A WAF whose running state cannot be read is not taken as matching.
	waf.heuristicsStatus.Store(500)
	before = waf.pushCount()
	if got := reconcileWAF(ctx, db, waf.srv.URL, auth, false); got != reconcileOK || waf.pushCount() != before+2 {
		t.Errorf("unreadable heuristics: outcome %v, %d pushes; want ok and every stored value pushed (%d)", got, waf.pushCount(), before+2)
	}
}
