package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

type settingsAuditRow struct {
	target  string
	details map[string]any
	raw     string
}

func lastSettingsAudit(t *testing.T, h *SettingsHandlers) (settingsAuditRow, int) {
	t.Helper()
	var n int
	_ = h.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='update_settings'").Scan(&n)
	var row settingsAuditRow
	_ = h.db.QueryRow("SELECT target, details FROM audit_log WHERE action='update_settings' ORDER BY id DESC LIMIT 1").Scan(&row.target, &row.raw)
	_ = json.Unmarshal([]byte(row.raw), &row.details)
	return row, n
}

// "Who changed what" recorded the keys a request carried, before validation
// and with no value: a section save of one field read "Changed 8 settings",
// and whether alerts were switched on or off could not be told from the log.
// A save now records the keys it changed, each with its old and new value.
func TestSettingsSaveAuditsWhatChangedFromWhatToWhat(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"enable_notifications": "false", "cache_size": "1000"})
	_, before := lastSettingsAudit(t, h)

	// A section save: one field changed, one sent unchanged.
	got := runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"enable_notifications": "true", "cache_size": "1000"})
	if got.Code != 200 {
		t.Fatalf("save: %d", got.Code)
	}
	row, after := lastSettingsAudit(t, h)
	if after != before+1 {
		t.Fatalf("%d audit rows for one save, want 1", after-before)
	}
	if row.target != "enable_notifications" {
		t.Errorf("target = %q, want only the key that changed", row.target)
	}
	changes, _ := row.details["changes"].(map[string]any)
	n, _ := changes["enable_notifications"].(map[string]any)
	if n["from"] != "false" || n["to"] != "true" {
		t.Errorf("details = %s, want enable_notifications from false to true", row.raw)
	}

	// The same values again change nothing and write no row.
	runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"enable_notifications": "true", "cache_size": "1000"})
	if _, again := lastSettingsAudit(t, h); again != after {
		t.Errorf("a save that changed nothing wrote %d audit rows", again-after)
	}
}

// A secret is never written to the audit log, only that it was set or cleared.
func TestSettingsSaveAuditsASecretWithoutItsValue(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	h := NewSettingsHandlers(db, cfg)
	const token = "123456:super-secret-bot-token"
	if got := runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"telegram_bot_token": token}); got.Code != 200 {
		t.Fatalf("save: %d", got.Code)
	}
	row, _ := lastSettingsAudit(t, h)
	if strings.Contains(row.raw, token) || strings.Contains(row.raw, "super-secret") {
		t.Fatalf("the audit log holds the secret: %s", row.raw)
	}
	secrets, _ := row.details["secrets"].(map[string]any)
	if secrets["telegram_bot_token"] != "set" {
		t.Errorf("details = %s, want telegram_bot_token set", row.raw)
	}
	// Sent again unchanged (the form re-sends a value it holds): no row.
	_, n1 := lastSettingsAudit(t, h)
	runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"telegram_bot_token": token})
	if _, n2 := lastSettingsAudit(t, h); n2 != n1 {
		t.Errorf("re-sending the same secret wrote an audit row")
	}
}

// A long value is kept cut, and says so.
func TestSettingsSaveAuditCutsALongValue(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)
	long := strings.Repeat("exe,", 300)
	runBulkUpdate(t, h, cfg.ConfigDir, map[string]string{"blocked_file_types": long[:len(long)-1]})
	row, _ := lastSettingsAudit(t, h)
	changes, _ := row.details["changes"].(map[string]any)
	c, _ := changes["blocked_file_types"].(map[string]any)
	to, _ := c["to"].(string)
	if c == nil || len(to) != auditValueMax || c["truncated"] != true {
		t.Errorf("long value recorded as %d chars, truncated %v; want %d and true", len(to), c["truncated"], auditValueMax)
	}
}

// The one-setting route records its change the same way.
func TestSettingUpdateAuditsItsChange(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	r := chi.NewRouter()
	asAdmin := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, withUserContext(req, "admin"))
		})
	}
	NewSettingsHandlers(db, cfg).Register(r, asAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/settings/cache_size", strings.NewReader(`{"value":"2500"}`)))
	if w.Code != 200 {
		t.Fatalf("PUT: %d %s", w.Code, w.Body.String())
	}
	var target, details string
	_ = db.QueryRow("SELECT target, details FROM audit_log WHERE action='update_setting' ORDER BY id DESC LIMIT 1").Scan(&target, &details)
	if target != "cache_size" || !strings.Contains(details, `"to":"2500"`) || !strings.Contains(details, `"from":"2000"`) || !strings.Contains(details, `"from":`) {
		t.Errorf("audit = %s %s, want cache_size with from and to", target, details)
	}
}
