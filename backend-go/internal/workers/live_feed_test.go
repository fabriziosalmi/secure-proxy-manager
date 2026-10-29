package workers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/websocket"
)

// The access-log page prepends live rows only when they match its filters
// (a client, an outcome, a rule, internal traffic hidden) and keys rows by
// id. A live row used to carry none of that: no id, no reason label, nothing
// saying whether its source is the stack's own, so the page could not hold
// it to the filter it shows. Each committed row now goes out with its id, its
// reason's label and its source's classification.
func TestLiveRowsCarryWhatThePageFiltersBy(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	SetLiveSourceClassifier(func(ip string) (bool, string) {
		if ip == "172.18.0.2" {
			return true, "Internal: the backend"
		}
		return false, "Private network address"
	})
	defer liveSources.Store(nil)

	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	backend := strings.Replace(lineAllowed, "192.168.88.50", "172.18.0.2", 1)
	if err := os.WriteFile(logPath, []byte(lineSinkholeGET+"\n"+backend+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hub := &websocket.Hub{Broadcast: make(chan []byte, 4)}
	if _, ok := tailOnce(db, hub, logPath, 0, squidTail); !ok {
		t.Fatal("tailOnce committed nothing")
	}
	if len(hub.Broadcast) != 2 {
		t.Fatalf("broadcast %d rows, want 2", len(hub.Broadcast))
	}
	var ids []int64
	rows, err := db.Query("SELECT id FROM proxy_logs ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()

	for i, want := range []struct {
		reason, label, kind string
		internal            bool
	}{
		{"domain_blacklist_dns", "Domain blacklist (DNS sinkhole)", "Private network address", false},
		{"none", "Allowed", "Internal: the backend", true},
	} {
		var got map[string]any
		if err := json.Unmarshal(<-hub.Broadcast, &got); err != nil {
			t.Fatal(err)
		}
		if id, _ := got["id"].(float64); int64(id) != ids[i] {
			t.Errorf("row %d: id %v, want the stored id %d", i, got["id"], ids[i])
		}
		if got["reason"] != want.reason || got["reason_label"] != want.label {
			t.Errorf("row %d: reason %v label %v, want %s / %s", i, got["reason"], got["reason_label"], want.reason, want.label)
		}
		if got["internal"] != want.internal || got["kind"] != want.kind {
			t.Errorf("row %d: internal %v kind %v, want %v / %s", i, got["internal"], got["kind"], want.internal, want.kind)
		}
	}
}
