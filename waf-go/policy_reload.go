package main

// The operator's policy (internal/policy) at run time: read at start-up,
// where a file that does not validate stops the WAF, and re-read when it
// changes, where it leaves the policy in force and says why.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/policy"
)

// policyPoll is how often the file is checked for a change.
const policyPoll = 5 * time.Second

var (
	policyPath = policy.DefaultPath
	// currentPolicy is read once per request; a reload swaps it whole. It
	// holds the empty policy from package initialization, before any init.
	currentPolicy = emptyPolicyPointer()

	policyReloadOK    atomic.Int64
	policyReloadError atomic.Int64
	// exceptionHits counts spm matches an exception took off a request (a
	// CRS rule taken off does not run, so it cannot be counted).
	exceptionHits atomic.Int64
	// wouldBlock counts requests the WAF would have blocked in observe mode.
	wouldBlock atomic.Int64

	policyMu sync.Mutex
	// policyStamp is the file's size and modification time when last read;
	// policyLastError is the last reload's failure, "" after a success.
	policyStamp     string
	policyLastError string
	policyLoadedAt  time.Time
)

func emptyPolicyPointer() *atomic.Pointer[policy.Policy] {
	p := &atomic.Pointer[policy.Policy]{}
	p.Store(policy.Empty())
	return p
}

// policyFileStamp is what the watcher compares: "" for a missing file.
func policyFileStamp(path string) (string, error) {
	st, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", st.Size(), st.ModTime().UnixNano()), nil
}

// loadPolicyAtStart reads the policy before the WAF serves. An error here
// is the caller's to stop on: a policy the operator wrote and the WAF
// ignored would be a silent fallback.
func loadPolicyAtStart() error {
	if p := os.Getenv("WAF_POLICY_FILE"); p != "" {
		policyPath = p
	}
	stamp, err := policyFileStamp(policyPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", policyPath, err)
	}
	p, err := policy.Load(policyPath, engine.KnownRuleID)
	if err != nil {
		return fmt.Errorf("%s: %w", policyPath, err)
	}
	currentPolicy.Store(p)
	policyMu.Lock()
	policyStamp, policyLoadedAt = stamp, time.Now()
	policyMu.Unlock()
	slog.Info("WAF policy loaded", "path", policyPath, "mode", p.Mode(), "exceptions", p.Exceptions(),
		"observe_rules", p.ObserveRules(), "observe_categories", p.ObserveCategories(), "sha256", p.Digest())
	return nil
}

// reloadPolicy re-reads the file when its stamp changed, or always when
// force is set. A file that does not validate leaves the policy in force.
// It returns whether the policy in force changed.
func reloadPolicy(force bool) (bool, error) {
	policyMu.Lock()
	defer policyMu.Unlock()
	stamp, err := policyFileStamp(policyPath)
	if err != nil {
		return false, recordReloadError(err)
	}
	if !force && stamp == policyStamp {
		return false, nil
	}
	p, err := policy.Load(policyPath, engine.KnownRuleID)
	if err != nil {
		// The stamp is kept, so a file that stays broken is reported once,
		// not every five seconds; the next edit is read again.
		policyStamp = stamp
		return false, recordReloadError(err)
	}
	policyStamp, policyLastError = stamp, ""
	if p.Digest() == currentPolicy.Load().Digest() {
		return false, nil
	}
	currentPolicy.Store(p)
	policyLoadedAt = time.Now()
	policyReloadOK.Add(1)
	// The verdicts change: Squid must drop its cached ones, and the safe
	// cache vouches for URLs scored under the old policy.
	atomic.AddUint64(&istagEpoch, 1)
	eng.SafeCache().Invalidate()
	slog.Info("WAF policy reloaded", "path", policyPath, "mode", p.Mode(), "exceptions", p.Exceptions(),
		"observe_rules", p.ObserveRules(), "observe_categories", p.ObserveCategories(), "sha256", p.Digest())
	return true, nil
}

// recordReloadError is called with policyMu held.
func recordReloadError(err error) error {
	policyLastError = err.Error()
	policyReloadError.Add(1)
	slog.Error("WAF policy not reloaded; the policy in force stays", "path", policyPath, "error", err.Error())
	return err
}

// watchPolicy checks the file every policyPoll until stop is closed.
func watchPolicy(stop <-chan struct{}) { watchPolicyEvery(stop, policyPoll) }

func watchPolicyEvery(stop <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_, _ = reloadPolicy(false)
		}
	}
}

// policyStatus is the policy in force, for GET /policy and POST /policy/reload.
func policyStatus() map[string]any {
	p := currentPolicy.Load()
	policyMu.Lock()
	defer policyMu.Unlock()
	return map[string]any{
		"path":               policyPath,
		"mode":               p.Mode(),
		"exceptions":         p.Exceptions(),
		"observe_rules":      p.ObserveRules(),
		"observe_categories": p.ObserveCategories(),
		"sha256":             p.Digest(),
		"loaded_at":          policyLoadedAt.UTC().Format(time.RFC3339),
		"last_error":         policyLastError,
	}
}

// PolicyHandler answers GET /policy with the policy in force.
func (h *MgmtHandlers) PolicyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": policyStatus()})
}

// PolicyReloadHandler re-reads the file now. A file that does not validate
// answers 422 with the reason, and the policy in force stays.
func (h *MgmtHandlers) PolicyReloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	changed, err := reloadPolicy(true)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "detail": err.Error(), "data": policyStatus()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "changed": changed, "data": policyStatus()})
}

// writePolicyMetrics adds the policy's counters to /metrics.
func writePolicyMetrics(w http.ResponseWriter) {
	p := currentPolicy.Load()
	observe := 0
	if p.Observe() {
		observe = 1
	}
	fmt.Fprintf(w,
		"# HELP waf_policy_exceptions Exceptions in the policy in force.\n"+
			"# TYPE waf_policy_exceptions gauge\n"+
			"waf_policy_exceptions %d\n"+
			"# HELP waf_policy_observe_mode Whether the whole WAF only observes (1) or blocks (0).\n"+
			"# TYPE waf_policy_observe_mode gauge\n"+
			"waf_policy_observe_mode %d\n"+
			"# HELP waf_policy_reloads_total Policy reloads, by result.\n"+
			"# TYPE waf_policy_reloads_total counter\n"+
			"waf_policy_reloads_total{result=\"ok\"} %d\n"+
			"waf_policy_reloads_total{result=\"error\"} %d\n"+
			"# HELP waf_exception_hits_total Rule matches an exception took off a request (rules the WAF matches itself).\n"+
			"# TYPE waf_exception_hits_total counter\n"+
			"waf_exception_hits_total %d\n"+
			"# HELP waf_would_block_total Requests the WAF would have blocked while it only observes.\n"+
			"# TYPE waf_would_block_total counter\n"+
			"waf_would_block_total %d\n",
		p.Exceptions(), observe, policyReloadOK.Load(), policyReloadError.Load(), exceptionHits.Load(), wouldBlock.Load())
}
