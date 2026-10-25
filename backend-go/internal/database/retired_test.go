package database

import (
	"path/filepath"
	"testing"
)

// A database at version 4 holding the retired settings (as every install did:
// the seed wrote several of them, and the settings page wrote the Tailscale
// and DDNS tokens in clear) loses exactly those rows, once.
func TestVersion5DeletesTheRetiredSettings(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "v4.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version = 4"); err != nil {
		t.Fatal(err)
	}
	for _, k := range RetiredSettings {
		if _, err := db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES(?, 'x')", k); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES('log_retention_days','12')")

	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	for _, k := range RetiredSettings {
		var n int
		_ = db.QueryRow("SELECT COUNT(*) FROM settings WHERE setting_name=?", k).Scan(&n)
		if n != 0 {
			t.Errorf("%s survived the migration (or the seed wrote it back)", k)
		}
	}
	var keep string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='log_retention_days'").Scan(&keep)
	if keep != "12" {
		t.Errorf("log_retention_days = %q: the migration touched a setting that is still used", keep)
	}
	var v int
	_ = db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != schemaVersion {
		t.Errorf("user_version = %d, want %d", v, schemaVersion)
	}
}

// The seed stores what the settings page shows and the services apply, so a
// fresh install has no fallback that differs from what runs.
func TestSeedStoresTheEffectiveDefaults(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"waf_h_entropy": "true", "waf_h_beaconing": "true", "waf_h_pii": "true",
		"waf_h_sharding": "true", "waf_h_ghosting": "true", "waf_h_sequence": "false",
		"bandwidth_limit_mbps": "100", "bandwidth_limit_per_user_kbps": "0",
		"time_restriction_start": "08:00", "time_restriction_end": "18:00",
		"blocked_file_types": DefaultBlockedFileTypes, "enable_content_filtering": "false",
	}
	for k, v := range want {
		var got string
		_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name=?", k).Scan(&got)
		if got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}
