package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/go-icap/icap"

	"secure-proxy-waf/internal/engine"
)

// drainNotifications empties the notification queue, which nothing consumes
// in the test binary, so a test reads only the alerts it caused.
func drainNotifications() {
	for {
		select {
		case <-notifyChan:
			notifyPending.Add(-1)
		default:
			return
		}
	}
}

func nextNotification(t *testing.T) map[string]interface{} {
	t.Helper()
	select {
	case a := <-notifyChan:
		notifyPending.Add(-1)
		return a
	case <-time.After(time.Second):
		t.Fatal("no notification was queued for the block")
		return nil
	}
}

// A blocked response is a WAF block like a blocked request: it carries an
// event ID on the 403, the same ID reaches the backend in the notification,
// and the notification names the client and the URL of the request whose
// response was blocked.
func TestRespmodBlocksCarryAnEventIDAndNotifyTheBackend(t *testing.T) {
	withEngine(t, engine.Config{})
	cases := []struct {
		name, contentType, body, category string
		rule                              string
	}{
		{"dangerous content type", "application/x-msdownload", "MZ fake executable", "DANGEROUS_CONTENT_TYPE", ""},
		{"leaked private key", "text/plain", "-----BEGIN RSA PRIVATE KEY-----\nMIIE", "RESPONSE_SECRET_LEAK", "RESP-004"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			drainNotifications()
			w := &mockResponseWriter{}
			req := &icap.Request{
				Header:  textproto.MIMEHeader{"X-Client-Ip": []string{"192.168.0.42"}},
				Request: httptest.NewRequest("GET", "http://downloads.example.com/file", nil),
				Response: &http.Response{
					Header:     http.Header{"Content-Type": []string{c.contentType}},
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader([]byte(c.body))),
				},
			}
			handleRespmod(w, req)

			resp, ok := w.resp.(*http.Response)
			if w.code != 200 || !ok || resp.StatusCode != 403 {
				t.Fatalf("want the 403 block page, got ICAP %d, %v", w.code, w.resp)
			}
			eventID := resp.Header.Get("X-WAF-Event-Id")
			if eventID == "" {
				t.Fatal("the blocked response carries no X-WAF-Event-Id, so its access log row cannot be joined to the block")
			}

			alert := nextNotification(t)
			d, _ := alert["details"].(map[string]interface{})
			if alert["event_type"] != "waf_block" || d == nil {
				t.Fatalf("notification is not a waf_block with details: %v", alert)
			}
			if d["event_id"] != eventID {
				t.Errorf("notification event_id %v, block page %q", d["event_id"], eventID)
			}
			if d["source"] != "RESPONSE" || d["category"] != c.category {
				t.Errorf("source %v category %v, want RESPONSE %s", d["source"], d["category"], c.category)
			}
			if d["client_ip"] != "192.168.0.42" || d["url"] != "http://downloads.example.com/file" {
				t.Errorf("client_ip %v url %v", d["client_ip"], d["url"])
			}
			if c.rule != "" {
				rules, _ := d["rules"].([]string)
				if !strings.Contains(strings.Join(rules, ","), c.rule) {
					t.Errorf("rules %v do not name %s", d["rules"], c.rule)
				}
			}
		})
	}
}

// Two blocked responses get two event IDs: the ID identifies one block.
func TestRespmodBlockEventIDsAreDistinct(t *testing.T) {
	withEngine(t, engine.Config{})
	ids := map[string]bool{}
	for i := 0; i < 2; i++ {
		drainNotifications()
		w := &mockResponseWriter{}
		handleRespmod(w, &icap.Request{Response: &http.Response{
			Header: http.Header{"Content-Type": []string{"application/java-archive"}}, StatusCode: 200,
			Body: io.NopCloser(strings.NewReader("PK")),
		}})
		resp, _ := w.resp.(*http.Response)
		if resp == nil {
			t.Fatal("no block page")
		}
		ids[resp.Header.Get("X-WAF-Event-Id")] = true
	}
	if len(ids) != 2 || ids[""] {
		t.Errorf("want two distinct non-empty event IDs, got %v", ids)
	}
}

// /metrics exposes the safe-URL cache: a hit and an entry show up as
// waf_safe_cache_hits_total and waf_safe_cache_size.
func TestMetricsExposeTheSafeURLCache(t *testing.T) {
	withEngine(t, engine.Config{})
	eng.SafeCache().MarkSafe("GET\x00http://example.com/")
	if !eng.SafeCache().IsSafe("GET\x00http://example.com/") {
		t.Fatal("setup: the marked URL is not in the cache")
	}
	w := httptest.NewRecorder()
	(&MgmtHandlers{}).MetricsHandler(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{"waf_safe_cache_hits_total 1\n", "waf_safe_cache_size 1\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q", strings.TrimSpace(want))
		}
	}
}
