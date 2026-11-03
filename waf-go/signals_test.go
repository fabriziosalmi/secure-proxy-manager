package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"secure-proxy-waf/internal/engine"
)

// freshSignals gives one test its own (client, category) table and an
// empty queue.
func freshSignals(t *testing.T) {
	t.Helper()
	prev := signalTable
	signalTable = newSignalSeen(signalSeenMax)
	t.Cleanup(func() { signalTable = prev })
	drainSignals()
}

func drainSignals() {
	for {
		select {
		case <-signalChan:
		default:
			return
		}
	}
}

func TestSignalSeenCoalesces(t *testing.T) {
	s := newSignalSeen(10)
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	steps := []struct {
		client, category string
		at               time.Duration
		send             bool
	}{
		{"192.0.2.1", "HEURISTIC_BEACONING", 0, true},
		{"192.0.2.1", "HEURISTIC_BEACONING", 9*time.Minute + 59*time.Second, false},
		{"192.0.2.1", "TYPOSQUATTING", time.Minute, true},
		{"192.0.2.2", "HEURISTIC_BEACONING", time.Minute, true},
		// Ten minutes after it was last sent, not after it was last seen.
		{"192.0.2.1", "HEURISTIC_BEACONING", 10 * time.Minute, true},
	}
	for _, st := range steps {
		send, full := s.admit(st.client, st.category, t0.Add(st.at))
		if send != st.send || full {
			t.Errorf("%s %s at +%v: send=%v full=%v, want send=%v", st.client, st.category, st.at, send, full, st.send)
		}
	}
}

func TestSignalSeenFullTable(t *testing.T) {
	s := newSignalSeen(2)
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	s.admit("a", "X", at(0))
	s.admit("b", "X", at(50*time.Second))
	steps := []struct {
		client     string
		at         time.Duration
		send, full bool
	}{
		// Full of recent pairs: dropped. This sweep finds nothing old.
		{"c", 5 * time.Minute, false, true},
		// a is old now and the last sweep was 5 minutes ago: this one
		// removes a and makes room.
		{"c", 10*time.Minute + 10*time.Second, true, false},
		// b turned old 5s ago, but the table was swept 45s ago: dropped.
		{"d", 10*time.Minute + 55*time.Second, false, true},
		// A minute after that sweep, the next one removes b.
		{"d", 11*time.Minute + 15*time.Second, true, false},
	}
	for _, st := range steps {
		send, full := s.admit(st.client, "X", at(st.at))
		if send != st.send || full != st.full {
			t.Errorf("%s at +%v: send=%v full=%v, want send=%v full=%v", st.client, st.at, send, full, st.send, st.full)
		}
	}
	if len(s.at) > 2 {
		t.Errorf("table holds %d pairs, max 2", len(s.at))
	}
}

func TestSignalsOf(t *testing.T) {
	got := signalsOf([]engine.MatchResult{
		{RuleID: "SQLI-001", Category: "SQL_INJECTION", Score: 10},
		{RuleID: "ML-TYPO-001", Category: "TYPOSQUATTING", Score: 5},
		{RuleID: "SEC-AWS-1", Category: "CLOUD_SECRETS", Score: 0},
		{RuleID: "SEC-AWS-2", Category: "CLOUD_SECRETS", Score: 0},
		{RuleID: "DLP-PEM", Category: "DATA_LEAK_PREVENTION", Score: 0},
		{RuleID: "DLP-GHP", Category: "DATA_LEAK_PREVENTION", Score: 10},
	})
	want := []signalItem{
		{Category: "TYPOSQUATTING", Rule: "ML-TYPO-001"},
		{Category: "CLOUD_SECRETS", Rule: "SEC-AWS-1", Observed: true},
		{Category: "DATA_LEAK_PREVENTION", Rule: "DLP-PEM"},
	}
	if len(got) != len(want) {
		t.Fatalf("signals = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("signal %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A request that reaches a typosquatted name queues one signal with the
// client and the host; the same again within signalCoalesce queues none; a
// request with no client address queues none and is counted.
func TestReqmodQueuesSignals(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	freshSignals(t)

	runReqmod(t, httptest.NewRequest(http.MethodConnect, "paypa1.com:443", nil), "192.0.2.7")
	var data map[string]interface{}
	select {
	case data = <-signalChan:
	default:
		t.Fatal("no signal queued for a typosquatted CONNECT")
	}
	items, _ := data["signals"].([]signalItem)
	if data["client_ip"] != "192.0.2.7" || data["host"] != "paypa1.com" || len(items) != 1 ||
		items[0].Category != "TYPOSQUATTING" || items[0].Observed || data["blocked"] != false {
		t.Errorf("signal = %+v", data)
	}
	if _, err := time.Parse(time.RFC3339Nano, data["ts"].(string)); err != nil || data["event_id"] == "" {
		t.Errorf("ts %v event_id %v", data["ts"], data["event_id"])
	}

	coalesced := signalCounts["coalesced"].Load()
	runReqmod(t, httptest.NewRequest(http.MethodConnect, "paypa1.com:443", nil), "192.0.2.7")
	select {
	case d := <-signalChan:
		t.Errorf("second request within %v queued %+v", signalCoalesce, d)
	default:
	}
	if signalCounts["coalesced"].Load() != coalesced+1 {
		t.Error("the repeated signal was not counted as coalesced")
	}

	noClient := signalCounts["no_client"].Load()
	runReqmod(t, httptest.NewRequest(http.MethodConnect, "rnicrosoft.com:443", nil), "")
	select {
	case d := <-signalChan:
		t.Errorf("a request without a client queued %+v", d)
	default:
	}
	if signalCounts["no_client"].Load() != noClient+1 {
		t.Error("the signal without a client was not counted")
	}

	// A plain request with no signal category queues nothing.
	runReqmod(t, httptest.NewRequest(http.MethodGet, "http://example.org/", nil), "192.0.2.7")
	select {
	case d := <-signalChan:
		t.Errorf("a clean request queued %+v", d)
	default:
	}
}

// Signals go to their own path, with the service token, and their failures
// are counted apart from the block alerts'.
func TestSignalDelivery(t *testing.T) {
	noRetryDelay(t)
	t.Setenv("INTERNAL_ALERT_TOKEN", "t0ken")
	var path, auth atomic.Value
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.URL.Path)
		auth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(status)
	}))
	defer srv.Close()
	t.Setenv("BACKEND_URL", srv.URL)

	drainSignals()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { signalWorker(stop); close(done) }()
	signalChan <- map[string]interface{}{"event_id": "e1"}
	deadline := time.Now().Add(2 * time.Second)
	for path.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	<-done
	if path.Load() != "/api/internal/signals" || auth.Load() != "Bearer t0ken" {
		t.Errorf("the signal worker delivered to %v with %v", path.Load(), auth.Load())
	}

	status = http.StatusUnauthorized
	alerts, signals := notifyFailed["rejected"].Load(), signalFailed["rejected"].Load()
	deliverBackend("/api/internal/signals", map[string]interface{}{"event_id": "e2"}, signalFailed)
	if signalFailed["rejected"].Load() != signals+1 || notifyFailed["rejected"].Load() != alerts {
		t.Errorf("a rejected signal counted as signal %d (want +1) and alert %d (want +0)",
			signalFailed["rejected"].Load()-signals, notifyFailed["rejected"].Load()-alerts)
	}
}

func TestMetricsExposeSignals(t *testing.T) {
	w := httptest.NewRecorder()
	(&MgmtHandlers{}).MetricsHandler(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, line := range []string{`waf_signals_total{result="queued"}`, `waf_signals_total{result="coalesced"}`,
		`waf_signals_total{result="table_full"}`, `waf_signals_failed_total{reason="rejected"}`} {
		if !strings.Contains(w.Body.String(), line) {
			t.Errorf("metrics lack %s", line)
		}
	}
}
