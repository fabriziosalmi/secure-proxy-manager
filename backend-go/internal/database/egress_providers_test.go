package database

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigration7CreatesEgressProviderTablesIdempotently(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v6.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	// Simulate a database at version 6 before migration 7 existed.
	_, _ = db.Exec("DROP TABLE IF EXISTS egress_provider_entries")
	_, _ = db.Exec("DROP TABLE IF EXISTS egress_providers")
	_, _ = db.Exec("DELETE FROM settings WHERE setting_name = 'egress_provider_refresh_hours'")
	if _, err := db.Exec("PRAGMA user_version = 6"); err != nil {
		t.Fatal(err)
	}

	// Migrate from v6 to v7.
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init v6->v7: %v", err)
	}
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != schemaVersion {
		t.Fatalf("user_version = %d, want %d", v, schemaVersion)
	}

	var refreshHours string
	if err := db.QueryRow("SELECT setting_value FROM settings WHERE setting_name = 'egress_provider_refresh_hours'").Scan(&refreshHours); err != nil || refreshHours != "24" {
		t.Fatalf("egress_provider_refresh_hours = %q (%v), want \"24\"", refreshHours, err)
	}

	// Insert a catalog provider and an entry to verify schema and uniqueness constraints.
	res, err := db.Exec(
		"INSERT INTO egress_providers(kind, name, url, enabled, last_refresh, last_commit, last_error, held_json) VALUES('catalog', 'cloudflare', '', 1, '2026-10-26T18:00:00Z', 'd03d319a255c', '', '')",
	)
	if err != nil {
		t.Fatalf("insert egress_providers: %v", err)
	}
	pid, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO egress_provider_entries(provider_id, cidr, family) VALUES(?, '1.1.1.0/24', 4)", pid); err != nil {
		t.Fatalf("insert egress_provider_entries: %v", err)
	}

	// Duplicate (kind, name) must fail.
	if _, err := db.Exec("INSERT INTO egress_providers(kind, name) VALUES('catalog', 'cloudflare')"); err == nil {
		t.Errorf("expected duplicate (kind, name) to fail uniqueness constraint")
	}
	// Duplicate URL for kind='url' must fail, while empty URL for multiple catalog rows is allowed.
	if _, err := db.Exec("INSERT INTO egress_providers(kind, name, url) VALUES('catalog', 'github', '')"); err != nil {
		t.Errorf("second catalog provider with empty url failed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO egress_providers(kind, name, url) VALUES('url', 'feed1', 'https://example.com/ips.txt')"); err != nil {
		t.Fatalf("insert first url provider: %v", err)
	}
	if _, err := db.Exec("INSERT INTO egress_providers(kind, name, url) VALUES('url', 'feed2', 'https://example.com/ips.txt')"); err == nil {
		t.Errorf("expected duplicate url for kind='url' to fail uniqueness constraint")
	}
	// Duplicate (provider_id, cidr) must fail.
	if _, err := db.Exec("INSERT INTO egress_provider_entries(provider_id, cidr, family) VALUES(?, '1.1.1.0/24', 4)", pid); err == nil {
		t.Errorf("expected duplicate (provider_id, cidr) to fail uniqueness constraint")
	}

	// Reopening and re-running Init on the v7 database must be idempotent and preserve rows.
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("re-Init on v7: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM egress_provider_entries WHERE provider_id = ?", pid).Scan(&count); err != nil || count != 1 {
		t.Fatalf("entries after re-Init = %d (%v), want 1", count, err)
	}
}

func TestExportUnionManualAndEnabledProviders(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "export.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}

	// Manual entries: one CIDR that overlaps with the enabled provider, one distinct CIDR, one domain.
	if _, err := db.Exec("INSERT INTO dst_allowlist(entry, type, description) VALUES('8.8.8.0/24', 'cidr', 'manual dns'), ('1.1.1.0/24', 'cidr', 'manual dup'), ('api.example.com', 'domain', 'manual dom')"); err != nil {
		t.Fatal(err)
	}

	// Enabled provider with 1.1.1.0/24 (duplicate of manual) and 9.9.9.0/24 + 2606:4700::/32.
	res1, err := db.Exec("INSERT INTO egress_providers(kind, name, enabled) VALUES('catalog', 'cloudflare', 1)")
	if err != nil {
		t.Fatalf("insert enabled provider: %v", err)
	}
	pid1, _ := res1.LastInsertId()
	for _, e := range []struct {
		cidr   string
		family int
	}{
		{"1.1.1.0/24", 4},
		{"9.9.9.0/24", 4},
		{"2606:4700::/32", 6},
	} {
		if _, err := db.Exec("INSERT INTO egress_provider_entries(provider_id, cidr, family) VALUES(?, ?, ?)", pid1, e.cidr, e.family); err != nil {
			t.Fatal(err)
		}
	}

	// Disabled provider whose entries must NOT be exported, though kept in egress_provider_entries.
	res2, err := db.Exec("INSERT INTO egress_providers(kind, name, enabled) VALUES('catalog', 'github', 0)")
	if err != nil {
		t.Fatalf("insert disabled provider: %v", err)
	}
	pid2, _ := res2.LastInsertId()
	if _, err := db.Exec("INSERT INTO egress_provider_entries(provider_id, cidr, family) VALUES(?, '140.82.112.0/20', 4)", pid2); err != nil {
		t.Fatal(err)
	}

	cfgDir := t.TempDir()
	if err := ExportBlacklistsToFiles(db, cfgDir); err != nil {
		t.Fatalf("ExportBlacklistsToFiles: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(cfgDir, "dst_allow_ip.txt"))
	if err != nil {
		t.Fatalf("read dst_allow_ip.txt: %v", err)
	}
	gotLines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	wantLines := []string{"1.1.1.0/24", "2606:4700::/32", "8.8.8.0/24", "9.9.9.0/24"}
	if strings.Join(gotLines, ",") != strings.Join(wantLines, ",") {
		t.Fatalf("dst_allow_ip.txt = %v, want %v", gotLines, wantLines)
	}

	// Verify lists.manifest.json covers the exported dst_allow_ip.txt with matching sha256 and bytes.
	mraw, err := os.ReadFile(filepath.Join(cfgDir, "lists.manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest struct {
		Files map[string]struct {
			SHA256 string `json:"sha256"`
			Bytes  int64  `json:"bytes"`
		} `json:"files"`
	}
	if err := json.Unmarshal(mraw, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	entry, ok := manifest.Files["dst_allow_ip.txt"]
	if !ok || entry.Bytes != int64(len(raw)) || entry.SHA256 == "" {
		t.Fatalf("manifest entry for dst_allow_ip.txt = %+v (len=%d)", entry, len(raw))
	}

	// Clearing manual dst_allowlist must not touch egress_provider_entries.
	if _, err := db.Exec("DELETE FROM dst_allowlist"); err != nil {
		t.Fatal(err)
	}
	if err := ExportBlacklistsToFiles(db, cfgDir); err != nil {
		t.Fatal(err)
	}
	rawAfterClear, err := os.ReadFile(filepath.Join(cfgDir, "dst_allow_ip.txt"))
	if err != nil {
		t.Fatal(err)
	}
	gotAfter := strings.Split(strings.TrimSpace(string(rawAfterClear)), "\n")
	wantAfter := []string{"1.1.1.0/24", "2606:4700::/32", "9.9.9.0/24"}
	if strings.Join(gotAfter, ",") != strings.Join(wantAfter, ",") {
		t.Fatalf("after clearing dst_allowlist, dst_allow_ip.txt = %v, want %v", gotAfter, wantAfter)
	}
}
