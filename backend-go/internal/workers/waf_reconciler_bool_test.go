package workers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// The reconciler reads a stored heuristic the way the Settings page shows it:
// only "true" is on. It used to treat "1" as on too, so a heuristic the page
// showed as off was switched on in the WAF.
func TestReconcilerReadsHeuristicsAsTheSettingsPageDoes(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	_, _ = db.Exec("DELETE FROM settings WHERE setting_name LIKE 'waf_h_%'")
	_, _ = db.Exec("INSERT INTO settings(setting_name,setting_value) VALUES('waf_h_entropy','1'),('waf_h_pii','true')")

	var mu sync.Mutex
	pushed := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/heuristics/toggle" {
			var b struct {
				Heuristic string `json:"heuristic"`
				Enabled   bool   `json:"enabled"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			mu.Lock()
			pushed[b.Heuristic] = b.Enabled
			mu.Unlock()
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	reconcileWAF(context.Background(), db, srv.URL, WAFAuth{User: "u", Pass: "p"}, true)
	mu.Lock()
	defer mu.Unlock()
	if on, ok := pushed["waf_h_entropy"]; !ok || on {
		t.Errorf("waf_h_entropy stored as \"1\": pushed enabled=%v (present %v), want false like the Settings page", on, ok)
	}
	if !pushed["waf_h_pii"] {
		t.Errorf("waf_h_pii stored as \"true\" was not pushed as enabled: %v", pushed)
	}
}
