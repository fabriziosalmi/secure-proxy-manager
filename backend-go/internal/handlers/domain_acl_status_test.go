package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

// The Overview's "blocked at DNS only" notice is driven by squid_domain_acl,
// which is the proxy's own record of what it did with the domain blacklist.
// The backend cannot see SPM_SQUID_DOMAIN_ACL_MAX, so without the record the
// field is null and the UI shows no notice, rather than one from a guess.
func TestDashboardReportsTheProxysDomainACLRecord(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAnalyticsHandlers(db, cfg)
	path := filepath.Join(cfg.ConfigDir, domainACLStatusFile)

	type resp struct {
		Data struct {
			ACL *DomainACLStatus `json:"squid_domain_acl"`
		} `json:"data"`
	}
	read := func() *DomainACLStatus {
		t.Helper()
		var r resp
		getJSON(t, h.DashboardSummary, "/api/dashboard/summary", &r)
		return r.Data.ACL
	}

	if got := read(); got != nil {
		t.Fatalf("no record: squid_domain_acl = %+v, want null", *got)
	}

	// The test deployment: 473,936 names over the default limit of 250,000.
	if err := os.WriteFile(path, []byte(`{"version": 1, "names": 473936, "limit": 250000, "held": false, "written_at": 1793000000}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := read()
	if got == nil || got.Names != 473936 || got.Limit != 250000 || got.Held || got.WrittenAt != 1793000000 {
		t.Fatalf("squid_domain_acl = %+v, want 473936 names, limit 250000, not held", got)
	}

	if err := os.WriteFile(path, []byte(`{"version": 1, "names": 12, "limit": 250000, "held": true, "written_at": 1793000000}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := read(); got == nil || !got.Held || got.Names != 12 {
		t.Fatalf("squid_domain_acl = %+v, want 12 names held", got)
	}

	// Anything the backend does not understand is no record, not "held".
	for _, bad := range []string{`not json`, `{"version": 2, "names": 1, "limit": 2, "held": true}`, `{"version": 1, "limit": 2, "held": true}`, `{"version": 1, "names": 1, "limit": 2}`} {
		if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := read(); got != nil {
			t.Errorf("record %q: squid_domain_acl = %+v, want null", bad, *got)
		}
	}
}
