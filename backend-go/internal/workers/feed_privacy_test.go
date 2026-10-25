package workers

import (
	"encoding/json"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/websocket"
)

// With gdpr_mode on the live log feed carries the masked client address, as
// GET /api/logs does; the Logs page shows both, and the live rows used to
// carry the full address while the table masked it.
func TestTheLiveFeedMasksClientAddressesInGDPRMode(t *testing.T) {
	read := func(mask bool) (string, string) {
		// A hub that is not running, so the test reads what was broadcast.
		hub := &websocket.Hub{Broadcast: make(chan []byte, 4)}
		entry := map[string]any{"source_ip": "192.168.1.77", "destination": "http://a.test/"}
		broadcastBatch(hub, []map[string]any{entry}, mask)
		var got map[string]any
		_ = json.Unmarshal(<-hub.Broadcast, &got)
		return got["source_ip"].(string), entry["source_ip"].(string)
	}
	if sent, kept := read(true); sent != "192.168.1.x" || kept != "192.168.1.77" {
		t.Errorf("masked: sent %q, entry left as %q; want 192.168.1.x and the entry untouched", sent, kept)
	}
	if sent, _ := read(false); sent != "192.168.1.77" {
		t.Errorf("unmasked: sent %q", sent)
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()
	_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES('gdpr_mode','true')")
	if !feedPrivacy(db).Enabled() {
		t.Error("the feed does not read gdpr_mode")
	}
}

// Whether a source is internal is read from its real address; masking it
// first made every masked row look external, and the Logs page showed the
// stack's own traffic it hides.
func TestTheMaskedFeedStillKnowsAnInternalSource(t *testing.T) {
	classify := func(ip string) (bool, string) {
		if ip == "172.18.0.1" {
			return true, "Internal: this host"
		}
		return false, "Private network address"
	}
	liveSources.Store(&classify)
	defer liveSources.Store(nil)
	hub := &websocket.Hub{Broadcast: make(chan []byte, 4)}
	broadcastBatch(hub, []map[string]any{{"source_ip": "172.18.0.1", "destination": "http://a.test/"}}, true)
	var got map[string]any
	_ = json.Unmarshal(<-hub.Broadcast, &got)
	if got["source_ip"] != "172.18.0.x" || got["internal"] != true || got["kind"] != "Internal: this host" {
		t.Errorf("masked internal row = %v; want 172.18.0.x, internal, its kind", got)
	}
}
