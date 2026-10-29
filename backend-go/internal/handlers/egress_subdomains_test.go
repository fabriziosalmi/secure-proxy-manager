package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// include_subdomains is the explicit way to allow a domain and every name
// under it. The leading dot meant the same and was the only way: a reader of
// the API, and of the form, had to know Squid's dstdomain syntax. The stored
// entry and the export are the leading-dot form either way, which the API
// still accepts; an address refuses the flag.
func TestEgressAllowlistIncludeSubdomainsStoresTheLeadingDotForm(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)

	for _, body := range []string{
		`{"entry":"updates.example.org","include_subdomains":true}`,
		`{"entry":".mirror.example.net"}`,
		`{"entry":"exact.example.com","include_subdomains":false}`,
	} {
		if code, out := call(t, h, "POST", "/api/egress-allowlist", body); code != http.StatusOK {
			t.Fatalf("%s = %d %v, want 200", body, code, out)
		}
	}
	// The flag on an entry that already has the dot does not double it.
	if code, out := call(t, h, "POST", "/api/egress-allowlist", `{"entry":".mirror.example.net","include_subdomains":true}`); code != http.StatusBadRequest {
		t.Errorf("a second .mirror.example.net = %d %v, want 400 (already listed, not ..mirror)", code, out)
	}
	if code, out := call(t, h, "POST", "/api/egress-allowlist", `{"entry":"203.0.113.0/24","include_subdomains":true}`); code != http.StatusBadRequest {
		t.Errorf("a network with include_subdomains = %d %v, want 400", code, out)
	}

	rows, err := db.Query("SELECT entry FROM dst_allowlist ORDER BY entry")
	if err != nil {
		t.Fatal(err)
	}
	var stored []string
	for rows.Next() {
		var e string
		_ = rows.Scan(&e)
		stored = append(stored, e)
	}
	rows.Close()
	want := []string{".mirror.example.net", ".updates.example.org", "exact.example.com"}
	if len(stored) != len(want) {
		t.Fatalf("stored %v, want %v", stored, want)
	}
	for i := range want {
		if stored[i] != want[i] {
			t.Errorf("stored %v, want %v", stored, want)
			break
		}
	}

	if err := database.ExportBlacklistsToFiles(db, cfg.ConfigDir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "dst_allow_domain.txt")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != ".mirror.example.net\n.updates.example.org\nexact.example.com\n" {
		t.Errorf("dst_allow_domain.txt = %q, want the leading-dot form for both subdomain entries", got)
	}
}
