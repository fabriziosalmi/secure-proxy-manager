package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTryPihole(t *testing.T) {
	// 1. Success case
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"domains_being_blocked": 1000, "gravity_last_updated": "2024-04-02"}`)
	}))
	defer ts.Close()

	client := ts.Client()
	res := tryPihole(client, "127.0.0.1", ts.URL)
	if res == nil || res.Type != "pihole" {
		t.Errorf("Expected pihole detection, got nil")
	}

	// 2. Failure case (not Pi-hole)
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"other": "data"}`)
	}))
	defer ts2.Close()
	res = tryPihole(client, "127.0.0.1", ts2.URL)
	if res != nil {
		t.Errorf("Expected nil for non-Pihole data, got %v", res)
	}

	// 3. Error case (404)
	ts3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts3.Close()
	res = tryPihole(client, "127.0.0.1", ts3.URL)
	if res != nil {
		t.Errorf("Expected nil for 404, got %v", res)
	}
}

func TestTryAdGuard(t *testing.T) {
	// 1. Success case
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"dns_addresses": ["192.168.1.1"], "version": "v0.107.0"}`)
	}))
	defer ts.Close()

	client := ts.Client()
	res := tryAdGuard(client, "127.0.0.1", ts.URL)
	if res == nil || res.Type != "adguard" {
		t.Errorf("Expected adguard detection, got nil")
	}

	// 2. Failure case
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"other": "data"}`)
	}))
	defer ts2.Close()
	res = tryAdGuard(client, "127.0.0.1", ts2.URL)
	if res != nil {
		t.Errorf("Expected nil for non-AdGuard data, got %v", res)
	}
}

func TestDetectLocalSubnet(t *testing.T) {
	subnet := detectLocalSubnet()
	// Should at least be formatted correctly if found, or empty if no interfaces
	if subnet != "" {
		// e.g. "192.168.1"
		if len(subnet) < 5 {
			t.Errorf("Subnet seems too short: %s", subnet)
		}
	}
}

func TestDNSDetectHandlers_Detect_Empty(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewDNSDetectHandlers(db)

	r := httptest.NewRequest("POST", "/api/dns/detect", nil)
	w := httptest.NewRecorder()
	// This will try to detect local subnet, then scan
	h.Detect(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Invalid JSON — falls back to autodetection silently.
	r = httptest.NewRequest("POST", "/api/dns/detect", bytes.NewBuffer([]byte("{invalid")))
	w = httptest.NewRecorder()
	h.Detect(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for invalid JSON (fallback to auto), got %d", w.Code)
	}
}

// SSRF guard: callers must not be able to aim the scanner at public IP space.
func TestDNSDetectHandlers_Detect_RejectsPublicSubnet(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewDNSDetectHandlers(db)

	for _, sub := range []string{"1.1.1", "8.8.8", "100.64.0", "169.254.169"} {
		r := httptest.NewRequest("POST", "/api/dns/detect", bytes.NewBufferString(`{"subnet":"`+sub+`"}`))
		w := httptest.NewRecorder()
		h.Detect(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("subnet=%q expected 400, got %d", sub, w.Code)
		}
	}

	// Sanity: a private subnet is accepted (returns 200, scan results may be empty).
	r := httptest.NewRequest("POST", "/api/dns/detect", bytes.NewBufferString(`{"subnet":"192.168.99"}`))
	w := httptest.NewRecorder()
	h.Detect(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("private subnet expected 200, got %d", w.Code)
	}
}
