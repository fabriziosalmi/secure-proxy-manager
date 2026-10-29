package database

import (
	"encoding/json"
	"path/filepath"
	"strings"
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

func TestVersion8RetiresThreeSettingsWithAuditAndTruncation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v7.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	// Reset to schema version 7 and clear audit_log to isolate migration 8.
	if _, err := db.Exec("DELETE FROM audit_log; PRAGMA user_version = 7"); err != nil {
		t.Fatal(err)
	}
	longRule := strings.Repeat("R", 70*1024)
	seed := map[string]string{
		"allowed_networks":    "10.0.0.0/8,192.168.0.0/16",
		"waf_block_threshold": "75",
		"waf_custom_rules":    longRule,
		"log_retention_days":  "14",
	}
	for k, v := range seed {
		if _, err := db.Exec("INSERT OR REPLACE INTO settings(setting_name, setting_value) VALUES(?, ?)", k, v); err != nil {
			t.Fatal(err)
		}
	}

	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init v7->v8: %v", err)
	}

	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != schemaVersion {
		t.Fatalf("user_version = %d, want %d", v, schemaVersion)
	}

	for _, k := range []string{"allowed_networks", "waf_custom_rules", "waf_block_threshold"} {
		var n int
		_ = db.QueryRow("SELECT COUNT(*) FROM settings WHERE setting_name = ?", k).Scan(&n)
		if n != 0 {
			t.Errorf("%s still has %d rows in settings after migration 8", k, n)
		}
	}
	var kept string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name = 'log_retention_days'").Scan(&kept)
	if kept != "14" {
		t.Errorf("log_retention_days = %q, want 14", kept)
	}

	rows, err := db.Query("SELECT username, target, details FROM audit_log WHERE action = 'retire_setting_value' ORDER BY target")
	if err != nil {
		t.Fatal(err)
	}
	type auditRec struct {
		user    string
		target  string
		details string
	}
	var got []auditRec
	for rows.Next() {
		var r auditRec
		if err := rows.Scan(&r.user, &r.target, &r.details); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		got = append(got, r)
	}
	rows.Close()

	if len(got) != 3 {
		t.Fatalf("retire_setting_value audit rows = %d, want 3", len(got))
	}

	byTarget := map[string]map[string]any{}
	for _, r := range got {
		if r.user != "system" {
			t.Errorf("audit user for %s = %q, want system", r.target, r.user)
		}
		var d map[string]any
		if err := json.Unmarshal([]byte(r.details), &d); err != nil {
			t.Fatalf("unmarshal details for %s (%q): %v", r.target, r.details, err)
		}
		byTarget[r.target] = d
	}

	if d := byTarget["allowed_networks"]; d["value"] != "10.0.0.0/8,192.168.0.0/16" || d["truncated"] != nil {
		t.Errorf("allowed_networks audit details = %v", d)
	}
	if d := byTarget["waf_block_threshold"]; d["value"] != "75" || d["truncated"] != nil {
		t.Errorf("waf_block_threshold audit details = %v", d)
	}
	if d := byTarget["waf_custom_rules"]; d["truncated"] != true {
		t.Errorf("waf_custom_rules truncated = %v, want true", d["truncated"])
	} else if val, _ := d["value"].(string); len(val) != 64*1024 || val != longRule[:64*1024] {
		t.Errorf("waf_custom_rules value len = %d, want %d", len(val), 64*1024)
	}

	// Reopening / re-running Init must not write any new audit rows.
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("second Init: %v", err)
	}
	var countAfterReopen int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'retire_setting_value'").Scan(&countAfterReopen)
	if countAfterReopen != 3 {
		t.Errorf("retire_setting_value rows after reopen = %d, want 3", countAfterReopen)
	}
}

func TestVersion8WithoutRetiredRowsWritesNoAudit(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v7_clean.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		"DELETE FROM settings WHERE setting_name IN ('allowed_networks','waf_custom_rules','waf_block_threshold');" +
			"DELETE FROM audit_log;" +
			"PRAGMA user_version = 7",
	); err != nil {
		t.Fatal(err)
	}
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatalf("Init v7->v8 (empty): %v", err)
	}
	var v int
	_ = db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != schemaVersion {
		t.Fatalf("user_version = %d, want %d", v, schemaVersion)
	}
	var auditCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'retire_setting_value'").Scan(&auditCount)
	if auditCount != 0 {
		t.Errorf("retire_setting_value audit rows = %d, want 0", auditCount)
	}
}
