package main

import (
	"net/http"
	"testing"
)

// Squid logs X-SPM-Reason from the ICAP response (the spm logformat's
// %{X-SPM-Reason}adapt::<last_h), and the backend stores a request as a WAF
// block only when it reads "waf" there. Both block paths go through
// sendBlockResponse: REQMOD (with an event id) and RESPMOD (without one).
// The header must be on the ICAP response, not on the HTTP 403 it carries,
// which a client-facing upstream response could also carry.
func TestBlockResponseNamesTheWAFInTheICAPHeader(t *testing.T) {
	for _, eventID := range []string{"evt-1", ""} {
		w := &mockResponseWriter{}
		sendBlockResponse(w, "XSS_ATTACKS", 12, eventID)
		if got := w.Header().Get("X-SPM-Reason"); got != "waf" {
			t.Errorf("event id %q: ICAP X-SPM-Reason = %q, want waf", eventID, got)
		}
		resp, ok := w.resp.(*http.Response)
		if !ok || resp.StatusCode != 403 {
			t.Fatalf("event id %q: no encapsulated 403 (%T)", eventID, w.resp)
		}
		if resp.Header.Get("X-SPM-Reason") != "" {
			t.Errorf("event id %q: X-SPM-Reason leaked into the HTTP response", eventID)
		}
	}
}
