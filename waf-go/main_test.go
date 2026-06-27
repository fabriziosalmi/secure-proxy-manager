package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-icap/icap"
)

// mockResponseWriter implements icap.ResponseWriter
type mockResponseWriter struct {
	header http.Header
	code   int
	resp   interface{}
}

func (m *mockResponseWriter) Header() http.Header {
	if m.header == nil {
		m.header = make(http.Header)
	}
	return m.header
}

func (m *mockResponseWriter) WriteHeader(code int, httpMessage interface{}, body bool) {
	m.code = code
	m.resp = httpMessage
}

func (m *mockResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func TestHandleOptions(t *testing.T) {
	w := &mockResponseWriter{}
	req := &icap.Request{}
	handleOptions(w, req)
	if w.code != 200 {
		t.Errorf("Expected 200, got %d", w.code)
	}
	if w.Header().Get("Methods") != "REQMOD, RESPMOD" {
		t.Errorf("Expected REQMOD, RESPMOD, got %s", w.Header().Get("Methods"))
	}
	if w.Header().Get("ISTag") == "" {
		t.Error("OPTIONS response must carry an ISTag (RFC 3507 §4.7)")
	}
}

// ISTag must be present on REQMOD/RESPMOD and must change when the effective
// ruleset changes, so Squid invalidates cached verdicts after a toggle.
func TestISTag(t *testing.T) {
	if istagBase == "" {
		initISTag()
	}
	first := currentISTag()
	if first == "" || first[0] != '"' {
		t.Fatalf("ISTag must be a non-empty quoted token, got %q", first)
	}

	// A REQMOD response carries it.
	w := &mockResponseWriter{}
	handleReqmod(w, &icap.Request{Request: httptest.NewRequest("GET", "http://example.com/safe", nil)})
	if got := w.Header().Get("ISTag"); got != first {
		t.Errorf("REQMOD ISTag = %q, want %q", got, first)
	}

	// A category toggle bumps the epoch → ISTag changes.
	atomic.AddUint64(&istagEpoch, 1)
	if second := currentISTag(); second == first {
		t.Errorf("ISTag did not change after ruleset change: still %q", second)
	}
}

func TestHandleReqmod_Basic(t *testing.T) {
	w := &mockResponseWriter{}
	req := &icap.Request{
		Request: httptest.NewRequest("GET", "http://example.com/safe", nil),
	}
	handleReqmod(w, req)
	// Should be 204 No Content for safe URL
	if w.code != 204 {
		t.Errorf("Expected 204, got %d", w.code)
	}
}

func TestHandleReqmod_Blocked(t *testing.T) {
	w := &mockResponseWriter{}
	// SQL Injection attempt
	req := &icap.Request{
		Request: httptest.NewRequest("GET", "http://example.com/login?u='OR+1=1--", nil),
	}
	// Set threshold low enough to block
	blockThreshold = 1
	handleReqmod(w, req)
	
	// Should be 200 OK with the block page attached to the response
	if w.code != 200 {
		t.Errorf("Expected 200 for block, got %d", w.code)
	}
	resp, ok := w.resp.(*http.Response)
	if !ok || resp == nil || resp.StatusCode != 403 {
		t.Errorf("Expected 403 response attached, got %v", w.resp)
	}
}

func TestHandleRespmod_Safe(t *testing.T) {
	w := &mockResponseWriter{}
	req := &icap.Request{
		Response: &http.Response{
			Header: make(http.Header),
			StatusCode: 200,
		},
	}
	handleRespmod(w, req)
	if w.code != 204 {
		t.Errorf("Expected 204, got %d", w.code)
	}
}

func TestHandleRespmod_Blocked(t *testing.T) {
	w := &mockResponseWriter{}
	req := &icap.Request{
		Response: &http.Response{
			Header: http.Header{"Content-Type": []string{"application/x-msdownload"}},
			StatusCode: 200,
			Body: io.NopCloser(bytes.NewReader([]byte("fake executable data"))),
		},
	}
	handleRespmod(w, req)
	if w.code != 200 {
		t.Errorf("Expected 200 for block, got %d", w.code)
	}
	resp, ok := w.resp.(*http.Response)
	if !ok || resp == nil || resp.StatusCode != 403 {
		t.Error("Expected 403 response for dangerous type")
	}
}

func TestNotifyBackend_NoAuth(t *testing.T) {
	// Should return early without panic if env not set
	notifyBackend(map[string]any{"test": "data"})
}

func TestHealthEndpoint(t *testing.T) {
	h := &MgmtHandlers{}
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	h.HealthHandler(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestStatsEndpoint(t *testing.T) {
	s := &statsCollector{
		destCounts:     make(map[string]int),
		categoryCounts: make(map[string]int),
		uaCounts:       make(map[string]int),
	}
	stats = s // global
	h := &MgmtHandlers{}
	req := httptest.NewRequest("GET", "/stats", nil)
	w := httptest.NewRecorder()
	h.StatsHandler(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestResetEndpoint(t *testing.T) {
	s := &statsCollector{}
	stats = s // global
	h := &MgmtHandlers{}
	req := httptest.NewRequest("POST", "/reset", nil)
	w := httptest.NewRecorder()
	h.ResetHandler(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestCategoriesEndpoint(t *testing.T) {
    h := &MgmtHandlers{}
    req := httptest.NewRequest("GET", "/categories", nil)
    w := httptest.NewRecorder()
    h.CategoriesHandler(w, req)
    
    if w.Code != http.StatusOK {
        t.Errorf("Expected 200, got %d", w.Code)
    }
}

func TestCategoriesToggleEndpoint(t *testing.T) {
	h := &MgmtHandlers{}
	body, _ := json.Marshal(map[string]any{"category": "SQLI", "enabled": false})
    req := httptest.NewRequest("POST", "/categories/toggle", bytes.NewReader(body))
    w := httptest.NewRecorder()
    h.CategoriesToggleHandler(w, req)
    
    if w.Code != http.StatusOK {
        t.Errorf("Expected 200, got %d", w.Code)
    }
}
