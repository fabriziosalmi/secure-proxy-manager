package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// The egress allowlist's domains reach Squid verbatim as a dstdomain ACL: an
// exact name allows that host, a leading dot allows the domain and every name
// under it, and "*.example.com" is a literal name that matches nothing. It was
// accepted and listed as allowed, while the proxy kept refusing it.
func TestEgressAllowlistRefusesAWildcardSquidWouldNotMatch(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)

	code, body := call(t, h, "POST", "/api/egress-allowlist", `{"entry":"*.example.org"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("*.example.org = %d %v, want 400", code, body)
	}
	if msg, _ := body["detail"].(string); !strings.Contains(msg, ".example.com, with a leading dot") {
		t.Errorf("refusal = %v, want it to name the leading-dot form", body)
	}
	for _, ok := range []string{".example.org", "api.example.net", "203.0.113.0/24"} {
		if code, body := call(t, h, "POST", "/api/egress-allowlist", `{"entry":"`+ok+`"}`); code != http.StatusOK {
			t.Errorf("%s = %d %v, want 200", ok, code, body)
		}
	}
	if err := database.ExportBlacklistsToFiles(db, cfg.ConfigDir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "dst_allow_domain.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != ".example.org\napi.example.net\n" {
		t.Errorf("dst_allow_domain.txt = %q, want the two names as typed", got)
	}

	// A backup is held to the same rule.
	m := NewMaintenanceHandlers(db, cfg)
	w := httptest.NewRecorder()
	m.RestoreConfig(w, httptest.NewRequest("POST", "/api/maintenance/restore-config",
		strings.NewReader(`{"backup_version":2,"lists":{"dst_allowlist":[{"value":"*.restored.example"}]}}`)))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"skipped_entries":1`) {
		t.Errorf("restore of a wildcard = %d %s, want it skipped", w.Code, w.Body.String())
	}
}
