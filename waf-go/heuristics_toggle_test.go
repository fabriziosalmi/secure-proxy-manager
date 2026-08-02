package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Runtime toggle changes engine behaviour without re-init (the core of #102).
func TestSetHeuristicEnabledRuntime(t *testing.T) {
	initHeuristics() // PIICounter on, max 5 by default

	body := strings.Repeat("a@b.com, ", 6) // 6 emails > max → should fire
	if _, score := CheckResponseHeuristics(body); score == 0 {
		t.Fatal("expected PII heuristic to fire with PIICounter on")
	}

	if ok := setHeuristicEnabled("waf_h_pii", false); !ok {
		t.Fatal("setHeuristicEnabled(waf_h_pii) returned false for a known key")
	}
	if _, score := CheckResponseHeuristics(body); score != 0 {
		t.Fatalf("expected no PII score after toggling waf_h_pii off, got %d", score)
	}
	if heuristicStates()["waf_h_pii"] {
		t.Fatal("heuristicStates still reports waf_h_pii enabled after toggle off")
	}

	if setHeuristicEnabled("waf_h_nonexistent", true) {
		t.Fatal("setHeuristicEnabled accepted an unknown key")
	}
}

func TestHeuristicsToggleHandler(t *testing.T) {
	initHeuristics()
	h := &MgmtHandlers{}

	post := func(bodyJSON string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/heuristics/toggle", strings.NewReader(bodyJSON))
		rec := httptest.NewRecorder()
		h.HeuristicsToggleHandler(rec, req)
		return rec
	}

	// Valid toggle off.
	if rec := post(`{"heuristic":"waf_h_ghosting","enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("valid toggle: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if heuristicStates()["waf_h_ghosting"] {
		t.Fatal("waf_h_ghosting still enabled after toggle-off via handler")
	}
	// Back on.
	if rec := post(`{"heuristic":"waf_h_ghosting","enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("re-enable: got %d, want 200", rec.Code)
	}
	if !heuristicStates()["waf_h_ghosting"] {
		t.Fatal("waf_h_ghosting not re-enabled via handler")
	}
	// Unknown heuristic → 400.
	if rec := post(`{"heuristic":"waf_h_bogus","enabled":true}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown heuristic: got %d, want 400", rec.Code)
	}
	// Missing heuristic → 400.
	if rec := post(`{"enabled":true}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing heuristic: got %d, want 400", rec.Code)
	}
	// Wrong method → 405.
	req := httptest.NewRequest(http.MethodGet, "/heuristics/toggle", nil)
	rec := httptest.NewRecorder()
	h.HeuristicsToggleHandler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: got %d, want 405", rec.Code)
	}
}

func TestHeuristicsHandlerReportsState(t *testing.T) {
	initHeuristics()
	setHeuristicEnabled("waf_h_sequence", true)
	req := httptest.NewRequest(http.MethodGet, "/heuristics", nil)
	rec := httptest.NewRecorder()
	(&MgmtHandlers{}).HeuristicsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	var out struct {
		Data map[string]bool `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Data["waf_h_sequence"] {
		t.Fatalf("expected waf_h_sequence=true in state, got %+v", out.Data)
	}
}

// Concurrent toggles + hot-path reads must be race-free (run with -race).
func TestHeuristicCfgConcurrentAccess(t *testing.T) {
	initHeuristics()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(on bool) { defer wg.Done(); setHeuristicEnabled("waf_h_entropy", on) }(i%2 == 0)
		go func() {
			defer wg.Done()
			_ = loadHeuristicCfg()
			CheckResponseHeuristics("x@y.com")
		}()
	}
	wg.Wait()
}
