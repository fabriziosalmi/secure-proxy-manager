package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"secure-proxy-waf/internal/engine"
)

// The alert of a block tells the backend enough to turn it into a policy
// exception: the host and path a policy scopes, which half blocked, and for
// a CRS block the argument each scoring rule matched, in the policy's own
// form.
func TestBlockAlertCarriesWhatAnExceptionNeeds(t *testing.T) {
	// As the default engine runs it: data leak prevention observes, so the
	// password's DLP-001 match is in rules and not in scoring_rules.
	withEngine(t, engine.Config{BlockThreshold: 10, ObserveCategories: []string{"DATA_LEAK_PREVENTION", "FINANCIAL_DATA", "CLOUD_SECRETS"}})
	withCRS(t, hybridCRS(t))
	drainNotifications()
	const u = "http://Tienda.Example:8080/tienda1/publico/autenticar.jsp?modo=entrar&login=caria&pwd=EnSaCad%24oRa&remember=on"
	handleReqmod(&mockResponseWriter{}, icapReq(httptest.NewRequest("GET", u, nil), "198.51.100.240"))
	d, _ := nextNotification(t)["details"].(map[string]interface{})
	got, _ := json.Marshal(map[string]interface{}{
		"host": d["host"], "path": d["path"], "blocked_by": d["blocked_by"],
		"first_rule": first(d["rules"]), "scoring_rules": d["scoring_rules"], "crs_targets": d["crs_targets"],
	})
	want := `{"blocked_by":"crs","crs_targets":[{"rule":"CRS-942290","target":"ARGS:pwd"}],"first_rule":"CRS-942290","host":"tienda.example","path":"/tienda1/publico/autenticar.jsp","scoring_rules":["CRS-942290"]}`
	if string(got) != want {
		t.Errorf("alert\n got %s\nwant %s", got, want)
	}
	if s, _ := d["crs_score"].(int); s < 5 {
		t.Errorf("crs_score %v, want the inbound score that blocked", d["crs_score"])
	}
}

// An spm block carries an empty target list, not null, and names spm.
func TestSPMBlockAlertNamesSPM(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	withCRS(t, nil)
	drainNotifications()
	handleReqmod(&mockResponseWriter{}, icapReq(httptest.NewRequest("GET", "http://a.example/x?u='%20or%201=1--", nil), "198.51.100.241"))
	d, _ := nextNotification(t)["details"].(map[string]interface{})
	b, _ := json.Marshal(d["crs_targets"])
	sr, _ := json.Marshal(d["scoring_rules"])
	if d["blocked_by"] != "spm" || string(b) != "[]" || d["host"] != "a.example" || d["path"] != "/x" || string(sr) != `["SQLi-006","SQLi-017"]` {
		t.Errorf("blocked_by %v, crs_targets %s, host %v, path %v, scoring_rules %s", d["blocked_by"], b, d["host"], d["path"], sr)
	}
}

func first(v interface{}) interface{} {
	if l, ok := v.([]string); ok && len(l) > 0 {
		return l[0]
	}
	return nil
}
