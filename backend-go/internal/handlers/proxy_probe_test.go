package handlers

import (
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func proxyStatusOf(t *testing.T, proxyURL string) string {
	t.Helper()
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.ProxyURL = proxyURL
	w := httptest.NewRecorder()
	NewAnalyticsHandlers(db, cfg).Status(w, httptest.NewRequest("GET", "/api/status", nil))
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	s, _ := resp.Data["proxy_status"].(string)
	return s
}

// The health probe used to GET the proxy URL: not a proxy request, so Squid
// answered 400 and logged a "- / NONE_NONE/400" row from the backend each
// time the sidebar polled /api/status (every 30 s per open tab, about 2,880
// rows a day on the test deployment). The probe now connects and closes
// without sending a byte: Squid has no request to log, and its access_log
// leaves out connections that never sent one (spm_has_request).
func TestProxyProbeSendsNoRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan int, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- -1
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(conn)
		got <- len(b)
	}()

	if s := proxyStatusOf(t, "http://"+ln.Addr().String()); s != "running" {
		t.Errorf("proxy_status = %q, want running for a proxy that accepts the connection", s)
	}
	select {
	case n := <-got:
		if n != 0 {
			t.Errorf("the probe sent %d bytes to the proxy, want none", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the probe never connected")
	}
}

func TestProxyProbeReportsAProxyThatRefusesConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	if s := proxyStatusOf(t, "http://"+addr); s != "error" {
		t.Errorf("proxy_status = %q, want error when nothing listens", s)
	}
	if s := proxyStatusOf(t, "::not a url"); s != "error" {
		t.Errorf("proxy_status = %q for an unparseable PROXY_URL, want error", s)
	}
}
