package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// The identifiers an operator filters on must be fields, not text inside a
// message: a block record has to carry the client, the event id (which joins to
// Squid's log and the traffic log), the categories and the rules.
func TestBlockRecordCarriesStructuredIdentifiers(t *testing.T) {
	buf := captureLog(t)

	r := httptest.NewRequest("GET", "http://example.com/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--", nil)
	runReqmod(t, r, "198.51.100.77")

	var rec map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "WAF BLOCKED" {
			rec = m
		}
	}
	if rec == nil {
		t.Fatalf("no structured WAF BLOCKED record in:\n%s", buf.String())
	}
	if rec["client_ip"] != "198.51.100.77" {
		t.Errorf("client_ip = %v", rec["client_ip"])
	}
	if id, _ := rec["event_id"].(string); id == "" {
		t.Errorf("event_id missing: %v", rec)
	}
	if cats, ok := rec["categories"].([]any); !ok || len(cats) == 0 {
		t.Errorf("categories is not a list field: %v", rec["categories"])
	}
	if rules, ok := rec["rules"].([]any); !ok || len(rules) == 0 {
		t.Errorf("rules is not a list field: %v", rec["rules"])
	}
	if _, ok := rec["score"].(float64); !ok {
		t.Errorf("score is not a number field: %v", rec["score"])
	}
}
