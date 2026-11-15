package handlers

import (
	"net/http"
	"testing"
)

// Each failure of the egress provider routes has its own status: an unknown
// provider is 404, and apply-held with nothing held is 409. All of them used
// to answer 400, which says the request itself was malformed.
func TestEgressProviderFailuresHaveTheirOwnStatus(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	feed, _ := newFakeProviderFeedServer(t, "d03d319a255c0000000000000000000000000031")
	feed.setCatalog("telegram", "149.154.160.0/20\n", "")
	h := egressRouter(t, db, cfg)
	for _, c := range []struct {
		method, path, body string
		want               int
	}{
		{"PUT", "/api/egress-providers/no-such-provider", `{"enabled":true}`, http.StatusNotFound},
		{"POST", "/api/egress-providers/no-such-provider/refresh", "", http.StatusNotFound},
		{"POST", "/api/egress-providers/no-such-provider/apply-held", "", http.StatusNotFound},
		// A catalog provider never enabled has no row yet: not found either.
		{"POST", "/api/egress-providers/telegram/apply-held", "", http.StatusNotFound},
	} {
		if code, out := call(t, h, c.method, c.path, c.body); code != c.want {
			t.Errorf("%s %s = %d %v, want %d", c.method, c.path, code, out, c.want)
		}
	}
	if code, out := call(t, h, "PUT", "/api/egress-providers/telegram", `{"enabled":true}`); code != http.StatusOK {
		t.Fatalf("enable telegram: %d %v", code, out)
	}
	if code, out := call(t, h, "POST", "/api/egress-providers/telegram/apply-held", ""); code != http.StatusConflict {
		t.Errorf("apply-held with nothing held = %d %v, want 409", code, out)
	}
}
