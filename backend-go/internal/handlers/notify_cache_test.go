package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
)

// countSettingsReads makes the queue count its reads of the settings.
func countSettingsReads(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	old := notifySettingsLoad
	notifySettingsLoad = func(db *sql.DB, encKey string) (map[string]string, bool) {
		n.Add(1)
		return old(db, encKey)
	}
	t.Cleanup(func() { notifySettingsLoad = old })
	return &n
}

func wafAlert(i int) models.InternalAlert {
	return models.InternalAlert{EventType: "waf_block", Message: "blocked", Details: map[string]any{"client_ip": "198.51.100.7", "category": "SQLI", "n": i}}
}

// A flood reads the settings once, not once per event: the read and the
// decryption of every secret were the dispatcher's cost while the 256-slot
// queue filled and dropped events.
func TestNotifyQueueReadsTheSettingsOnceForABurst(t *testing.T) {
	reads := countSettingsReads(t)
	rig, h := newQueueRig(t, nil)
	for i := 0; i < 50; i++ {
		postAlert(t, h, wafAlert(i))
	}
	rig.sync()
	if got := reads.Load(); got != 1 {
		t.Fatalf("50 events read the settings %d times, want 1", got)
	}
	if got := len(rig.stop(t)); got == 0 {
		t.Fatal("no notification delivered")
	}
}

// A save through the settings handlers applies to the very next event, as
// the page promises for these settings (Live), with no wait for the cache.
func TestNotifyQueueAppliesASaveToTheNextEvent(t *testing.T) {
	rig, h := newQueueRig(t, nil)
	postAlert(t, h, wafAlert(1))
	rig.sync()
	settings := NewSettingsHandlers(h.db, h.cfg)
	if _, _, status, msg := settings.persistSettings(map[string]string{"enable_notifications": "false"}, nil); status != 0 {
		t.Fatalf("save: %d %s", status, msg)
	}
	postAlert(t, h, wafAlert(2))
	rig.sync()
	if got := len(rig.stop(t)); got != 1 {
		t.Fatalf("delivered %d notifications, want 1: the event after the save went out with notifications off", got)
	}
}

// A change made outside the handlers (sqlite3 on the data volume) reaches the
// queue once the cache's lifetime has passed.
func TestNotifyQueueRereadsTheSettingsAfterTheirLifetime(t *testing.T) {
	reads := countSettingsReads(t)
	rig, h := newQueueRig(t, nil)
	postAlert(t, h, wafAlert(1))
	rig.sync()
	if _, err := h.db.Exec("UPDATE settings SET setting_value='false' WHERE setting_name='enable_notifications'"); err != nil {
		t.Fatal(err)
	}
	rig.clock.Advance(notifySettingsTTL + time.Second)
	postAlert(t, h, wafAlert(2))
	rig.sync()
	if got := len(rig.stop(t)); got != 1 {
		t.Fatalf("delivered %d notifications, want 1 after the lifetime passed", got)
	}
	if got := reads.Load(); got < 2 {
		t.Fatalf("read the settings %d times, want a second read after the lifetime", got)
	}
}

// Every handler that writes the settings table marks the cache stale.
func TestSettingsWritersMarkTheNotificationSettingsStale(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	check := func(name string, write func()) {
		t.Helper()
		before := notifySettingsGeneration.Load()
		write()
		if notifySettingsGeneration.Load() == before {
			t.Errorf("%s did not mark the notification settings stale", name)
		}
	}
	check("persistSettings (POST and PUT /api/settings)", func() {
		if _, _, status, msg := NewSettingsHandlers(db, cfg).persistSettings(map[string]string{"enable_notifications": "true"}, nil); status != 0 {
			t.Fatalf("save: %d %s", status, msg)
		}
	})
	check("config restore", func() {
		w := httptest.NewRecorder()
		body := `{"backup_version":2,"settings":{"enable_notifications":"false"}}`
		NewMaintenanceHandlers(db, cfg).RestoreConfig(w, withUserContext(httptest.NewRequest(http.MethodPost, "/api/maintenance/restore-config", strings.NewReader(body)), "admin"))
		if w.Code != http.StatusOK {
			t.Fatalf("restore answered %d: %s", w.Code, w.Body.String())
		}
	})
	check("database reset", func() {
		w := httptest.NewRecorder()
		NewDatabaseHandlers(db).Reset(w, httptest.NewRequest(http.MethodPost, "/api/database/reset", strings.NewReader("{}")))
		if w.Code != http.StatusOK {
			t.Fatalf("reset answered %d: %s", w.Code, w.Body.String())
		}
	})
}
