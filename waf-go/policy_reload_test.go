package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"secure-proxy-waf/internal/engine"
)

// withPolicyFile points the WAF at a policy file in a temporary directory,
// writes doc into it ("" leaves it missing) and loads it. Everything is put
// back afterwards.
func withPolicyFile(t *testing.T, doc string) string {
	t.Helper()
	prevPath, prevPol := policyPath, currentPolicy.Load()
	policyMu.Lock()
	prevStamp, prevErr := policyStamp, policyLastError
	policyMu.Unlock()
	t.Cleanup(func() {
		policyPath = prevPath
		currentPolicy.Store(prevPol)
		policyMu.Lock()
		policyStamp, policyLastError = prevStamp, prevErr
		policyMu.Unlock()
	})
	policyPath = filepath.Join(t.TempDir(), "waf_policy.json")
	if doc != "" {
		writePolicy(t, doc)
	}
	if _, err := reloadPolicy(true); err != nil {
		t.Fatal(err)
	}
	return policyPath
}

// writePolicy replaces the file and moves its time on, so the watcher's
// size-and-mtime stamp changes even within one clock tick.
var policyWrites atomic.Int64

func writePolicy(t *testing.T, doc string) {
	t.Helper()
	if err := os.WriteFile(policyPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(time.Duration(policyWrites.Add(1)) * time.Second)
	if err := os.Chtimes(policyPath, when, when); err != nil {
		t.Fatal(err)
	}
}

const sqliURL = "http://shop.example/x?q='%20union%20select%20password%20from%20users--"

// An exception written to the file takes effect at the next check, without
// a restart; a broken edit leaves it in force; removing the file removes it.
func TestPolicyReloadsWithoutARestart(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withCRS(t, nil)
	withPolicyFile(t, "")
	if v := runReqmod(t, httptest.NewRequest("GET", sqliURL, nil), "198.51.100.60"); v.Action != "block" {
		t.Fatalf("no policy: %s, want block", v)
	}

	tag := currentISTag()
	eng.SafeCache().MarkSafe("GET\x00http://shop.example/cached")
	writePolicy(t, `{"version":1,"exceptions":[{"rule":"SQLi-001","host":"shop.example"}]}`)
	if changed, err := reloadPolicy(false); !changed || err != nil {
		t.Fatalf("reload after an edit: changed %v, err %v", changed, err)
	}
	if v := runReqmod(t, httptest.NewRequest("GET", sqliURL, nil), "198.51.100.61"); v.Action != "allow" {
		t.Errorf("SQLi-001 excepted on shop.example: %s, want allow", v)
	}
	if currentISTag() == tag {
		t.Error("the ISTag did not change with the policy")
	}
	if eng.SafeCache().IsSafe("GET\x00http://shop.example/cached") {
		t.Error("the safe cache kept a URL scored under the old policy")
	}
	if changed, err := reloadPolicy(false); changed || err != nil {
		t.Errorf("a reload with no edit: changed %v, err %v", changed, err)
	}

	writePolicy(t, `{"version":1,"exceptions":[{"rule":"SQLi-001"}]}`)
	if changed, err := reloadPolicy(false); changed || err == nil {
		t.Fatalf("a broken edit: changed %v, err %v", changed, err)
	}
	if v := runReqmod(t, httptest.NewRequest("GET", sqliURL, nil), "198.51.100.62"); v.Action != "allow" {
		t.Errorf("after a broken edit the policy in force must stay: %s", v)
	}
	if st := policyStatus(); !strings.Contains(st["last_error"].(string), "no host, path or target") {
		t.Errorf("the failure is not reported: %v", st["last_error"])
	}
	if _, err := reloadPolicy(false); err != nil {
		t.Errorf("a broken file is reported once, not at every check: %v", err)
	}

	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	if changed, err := reloadPolicy(false); !changed || err != nil {
		t.Fatalf("removing the file: changed %v, err %v", changed, err)
	}
	if v := runReqmod(t, httptest.NewRequest("GET", sqliURL, nil), "198.51.100.63"); v.Action != "block" {
		t.Errorf("file removed: %s, want block", v)
	}
}

// The watcher picks an edit up on its own.
func TestPolicyWatcherPicksUpAnEdit(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withPolicyFile(t, "")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { watchPolicyEvery(stop, 10*time.Millisecond); close(done) }()
	defer func() { close(stop); <-done }()
	writePolicy(t, `{"version":1,"mode":"observe"}`)
	deadline := time.Now().Add(2 * time.Second)
	for !currentPolicy.Load().Observe() {
		if time.Now().After(deadline) {
			t.Fatal("the watcher did not load the edit")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// In observe mode a request that would be blocked passes, and the record
// says it would not have.
func TestObserveModePassesAndRecords(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withCRS(t, nil)
	withPolicyFile(t, `{"version":1,"mode":"observe"}`)
	before := wouldBlock.Load()
	prevLog := trafficLog
	trafficLog = &TrafficLogger{ch: make(chan TrafficFeature, 8)}
	defer func() { trafficLog = prevLog }()
	w := &mockResponseWriter{}
	handleReqmod(w, icapReq(httptest.NewRequest("GET", sqliURL, nil), "198.51.100.64"))
	if w.code != 204 {
		t.Errorf("ICAP %d, want 204", w.code)
	}
	f := <-trafficLog.ch
	if f.Action != "allow" || !f.WouldBlock || f.WAFScore < 10 {
		t.Errorf("record: action %s, would_block %v, score %d", f.Action, f.WouldBlock, f.WAFScore)
	}
	if wouldBlock.Load() != before+1 {
		t.Error("waf_would_block_total did not count it")
	}
}

func TestPolicyEndpointsAndMetrics(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withPolicyFile(t, `{"version":1,"exceptions":[{"rule":"SQLi-001","host":"shop.example","comment":"vendor search"}]}`)
	h := &MgmtHandlers{}

	w := httptest.NewRecorder()
	h.PolicyHandler(w, httptest.NewRequest("GET", "/policy", nil))
	if !strings.Contains(w.Body.String(), `"exceptions":1`) || !strings.Contains(w.Body.String(), `"mode":"block"`) {
		t.Errorf("GET /policy: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	h.PolicyReloadHandler(w, httptest.NewRequest("GET", "/policy/reload", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /policy/reload: %d", w.Code)
	}
	writePolicy(t, `{"version":1,"mode":"learn"}`)
	w = httptest.NewRecorder()
	h.PolicyReloadHandler(w, httptest.NewRequest("POST", "/policy/reload", nil))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `mode \"learn\"`) {
		t.Errorf("POST /policy/reload with a broken file: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	h.HealthHandler(w, httptest.NewRequest("GET", "/health", nil))
	if !strings.Contains(w.Body.String(), `"policy":{"mode":"block","exceptions":1,"reload_failed":true}`) ||
		strings.Contains(w.Body.String(), "shop.example") || strings.Contains(w.Body.String(), "learn") {
		t.Errorf("/health: %s", w.Body.String())
	}

	writePolicy(t, `{"version":1,"mode":"observe"}`)
	w = httptest.NewRecorder()
	h.PolicyReloadHandler(w, httptest.NewRequest("POST", "/policy/reload", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"changed":true`) {
		t.Errorf("POST /policy/reload: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.MetricsHandler(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{"waf_policy_exceptions 0", "waf_policy_observe_mode 1", `waf_policy_reloads_total{result="error"}`, "waf_exception_hits_total", "waf_would_block_total"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("/metrics has no %q", want)
		}
	}
}

// A policy file that does not validate stops the WAF at start-up, and says
// which file and why. Run as a child, since the check is at start-up.
func TestBrokenPolicyStopsTheWAF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"exceptions":[{"rule":"SQLi-9999","host":"a.example"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "WAF_POLICY_FILE="+path)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("exit: %v, want status 1\n%s", err, out)
	}
	if !strings.Contains(string(out), "WAF not started") || !strings.Contains(string(out), `\"SQLi-9999\": no such rule`) {
		t.Errorf("the reason is not in the output:\n%s", out)
	}
}

// Requests and reloads at once: every request is answered, and with -race
// the swap is shown to be free of data races. (A request reads the policy
// once, in handleReqmod, so it cannot see half of two.)
func TestReloadUnderLoad(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withCRS(t, nil)
	withPolicyFile(t, "")
	on := `{"version":1,"exceptions":[{"rule":"SQLi-001","host":"shop.example"}]}`
	off := `{"version":1,"observe_rules":["XSS-003"]}`
	prevLog := trafficLog
	trafficLog = nil
	defer func() { trafficLog = prevLog }()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var bad atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				w := &mockResponseWriter{}
				handleReqmod(w, icapReq(httptest.NewRequest("GET", sqliURL, nil), fmt.Sprintf("198.51.100.%d", 70+i)))
				if w.code != 204 && w.code != 200 {
					bad.Add(1)
				}
			}
		}(i)
	}
	for n := 0; n < 100; n++ {
		doc := on
		if n%2 == 1 {
			doc = off
		}
		writePolicy(t, doc)
		if _, err := reloadPolicy(false); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if bad.Load() != 0 {
		t.Errorf("%d requests answered neither 204 nor a block page", bad.Load())
	}
	if !strings.Contains(policyStatus()["sha256"].(string), currentPolicy.Load().Digest()) {
		t.Error("status and policy in force disagree")
	}
}
