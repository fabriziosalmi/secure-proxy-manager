package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMaintenanceHandlers_BackupConfig(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	r := httptest.NewRequest("GET", "/api/maintenance/backup-config", nil)
	w := httptest.NewRecorder()
	h.BackupConfig(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	// The export is now an envelope: settings plus the lists that carry the
	// product's content, with a version an importer can check (SECURE-DATA-04).
	var resp struct {
		Status string `json:"status"`
		Data   struct {
			BackupVersion int               `json:"backup_version"`
			Settings      map[string]string `json:"settings"`
			Lists         map[string]any    `json:"lists"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data.Settings["proxy_port"] != "3128" {
		t.Errorf("Expected proxy_port 3128, got %s", resp.Data.Settings["proxy_port"])
	}
	if resp.Data.BackupVersion == 0 {
		t.Error("the export carries no backup_version — an importer cannot tell the shape")
	}
	if resp.Data.Lists == nil {
		t.Error("the export carries no lists — it is settings-only, which is the finding")
	}
}

func TestMaintenanceHandlers_RestoreConfig(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	body, _ := json.Marshal(map[string]any{
		"config": map[string]string{"proxy_port": "8080"},
	})
	r := httptest.NewRequest("POST", "/api/maintenance/restore-config", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.RestoreConfig(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var val string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='proxy_port'").Scan(&val)
	if val != "8080" {
		t.Errorf("Expected 8080, got %s", val)
	}
}

func TestMaintenanceHandlers_DownloadCA(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	// Test not found
	r := httptest.NewRequest("GET", "/api/security/download-ca", nil)
	w := httptest.NewRecorder()
	h.DownloadCA(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Create dummy cert
	certPath := filepath.Join(cfg.ConfigDir, "ssl_cert.pem")
	_ = os.MkdirAll(cfg.ConfigDir, 0750)
	_ = os.WriteFile(certPath, []byte("dummy cert"), 0644)
	defer os.Remove(certPath)

	w = httptest.NewRecorder()
	h.DownloadCA(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/x-x509-ca-cert" {
		t.Errorf("Expected cert content type, got %s", w.Header().Get("Content-Type"))
	}
}

func TestMaintenanceHandlers_CheckCertSecurity(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	r := httptest.NewRequest("GET", "/api/maintenance/check-cert-security", nil)
	w := httptest.NewRecorder()
	h.CheckCertSecurity(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var resp struct {
		Status string `json:"status"`
		Data   struct {
			Issues []string `json:"issues"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Status != "error" { // because dummy is missing initially
		t.Errorf("Expected error status for missing cert, got %v", resp.Status)
	}
}

// assertTrigger fails unless name exists in cfg.ConfigDir and holds a plausible
// unix timestamp. The trigger file IS the observable effect of these handlers —
// the proxy watchdog polls its mtime — so asserting only on the 200 would let
// the write be deleted outright without a test noticing, since every one of
// these handlers reports success whether or not the write succeeded.
func assertTrigger(t *testing.T, dir, name string) {
	t.Helper()
	path := filepath.Join(dir, name)
	body, err := os.ReadFile(path) // #nosec G304 — test-controlled temp dir
	if err != nil {
		t.Fatalf("trigger %s was not written: %v", name, err)
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		t.Fatalf("trigger %s: want a unix timestamp, got %q", name, body)
	}
	if delta := time.Since(time.Unix(ts, 0)); delta < 0 || delta > time.Minute {
		t.Errorf("trigger %s: timestamp %d is %v away from now", name, ts, delta)
	}
}

func TestMaintenanceHandlers_ReloadConfig(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)
	h.reloadAckTimeout = 200 * time.Millisecond // no watchdog here to answer

	r := httptest.NewRequest("POST", "/api/maintenance/reload-config", nil)
	w := httptest.NewRecorder()
	h.ReloadConfig(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	assertTrigger(t, cfg.ConfigDir, ".reload-squid")

	// A second call must re-trigger: the watchdog compares mtime, so an
	// unchanged file would be a silently ignored reload.
	before, err := os.Stat(filepath.Join(cfg.ConfigDir, ".reload-squid"))
	if err != nil {
		t.Fatalf("stat trigger: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	h.ReloadConfig(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/maintenance/reload-config", nil))
	after, err := os.Stat(filepath.Join(cfg.ConfigDir, ".reload-squid"))
	if err != nil {
		t.Fatalf("stat trigger after second reload: %v", err)
	}
	if !after.ModTime().After(before.ModTime()) {
		t.Errorf("second reload did not advance the trigger mtime (%v -> %v)", before.ModTime(), after.ModTime())
	}

	// ReloadConfig also exports the blacklists before signalling.
	if _, err := os.Stat(filepath.Join(cfg.ConfigDir, "ip_blacklist.txt")); err != nil {
		t.Errorf("reload did not export ip_blacklist.txt: %v", err)
	}
}

func TestMaintenanceHandlers_ReloadDNS(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	if _, err := db.Exec("INSERT INTO domain_blacklist (domain) VALUES (?)", "blocked.example"); err != nil {
		t.Fatalf("seed domain_blacklist: %v", err)
	}

	r := httptest.NewRequest("POST", "/api/maintenance/reload-dns", nil)
	w := httptest.NewRecorder()
	h.ReloadDNS(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	assertTrigger(t, cfg.ConfigDir, ".reload-dns")

	// The seeded domain must reach the exported file the DNS sinkhole reads,
	// and the reported count must match what was exported.
	exported, err := os.ReadFile(filepath.Join(cfg.ConfigDir, "domain_blacklist.txt")) // #nosec G304
	if err != nil {
		t.Fatalf("domain_blacklist.txt was not exported: %v", err)
	}
	if !strings.Contains(string(exported), "blocked.example") {
		t.Errorf("exported blacklist is missing the seeded domain: %q", exported)
	}
	var resp struct {
		Data struct {
			Domains int `json:"domains"`
		} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data.Domains != 1 {
		t.Errorf("Expected 1 domain reported, got %d", resp.Data.Domains)
	}
}

func TestMaintenanceHandlers_ClearCache(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	r := httptest.NewRequest("POST", "/api/maintenance/clear-cache", nil)
	w := httptest.NewRecorder()
	h.ClearCache(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	assertTrigger(t, cfg.ConfigDir, ".clear-cache")
}

// SECURE-DATA-04: the export must carry the state an operator cannot
// reconstruct — the lists — not just the toggles, and a round trip must
// actually restore them.
func TestBackupRestoreRoundTripsTheLists(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewMaintenanceHandlers(db, cfg)

	for _, q := range []string{
		`INSERT INTO ip_blacklist(ip, description) VALUES('203.0.113.9','bad host')`,
		`INSERT INTO domain_blacklist(domain, description) VALUES('malware.example','feed')`,
		`INSERT INTO ip_whitelist(ip, description) VALUES('10.0.0.7','printer')`,
		`INSERT INTO dst_allowlist(entry, type, description) VALUES('example.com','domain','allowed')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	w := httptest.NewRecorder()
	h.BackupConfig(w, httptest.NewRequest("GET", "/api/maintenance/backup-config", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("backup: %d", w.Code)
	}
	var backup struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&backup); err != nil {
		t.Fatalf("decode: %v", err)
	}
	lists, ok := backup.Data["lists"].(map[string]any)
	if !ok {
		t.Fatal("the export contains no `lists` — it is settings-only, which is the finding")
	}
	for _, name := range []string{"ip_blacklist", "domain_blacklist", "ip_whitelist", "dst_allowlist"} {
		entries, _ := lists[name].([]any)
		if len(entries) == 0 {
			t.Errorf("%s is empty in the export", name)
		}
	}

	// Wipe, then restore from the export.
	for _, tbl := range []string{"ip_blacklist", "domain_blacklist", "ip_whitelist", "dst_allowlist"} {
		if _, err := db.Exec("DELETE FROM " + tbl); err != nil {
			t.Fatalf("wipe: %v", err)
		}
	}
	payload, _ := json.Marshal(backup.Data)
	w2 := httptest.NewRecorder()
	h.RestoreConfig(w2, httptest.NewRequest("POST", "/api/maintenance/restore-config", bytes.NewReader(payload)))
	if w2.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w2.Code, w2.Body.String())
	}

	for tbl, want := range map[string]string{
		"ip_blacklist":     "203.0.113.9",
		"domain_blacklist": "malware.example",
		"ip_whitelist":     "10.0.0.7",
	} {
		var n int
		col := "ip"
		if tbl == "domain_blacklist" {
			col = "domain"
		}
		if err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s = ?", tbl, col), want).Scan(&n); err != nil {
			t.Fatalf("verify %s: %v", tbl, err)
		}
		if n != 1 {
			t.Errorf("%s: %q was not restored", tbl, want)
		}
	}
}

// SECURE-ARCH-02: the reload must report what the proxy actually did, not
// merely that a trigger file was written. Writing the trigger and returning
// success told the caller nothing — whether the watchdog was alive, whether the
// generator succeeded and whether squid accepted the config were all invisible.
func TestReloadConfigReportsWhatTheProxyDid(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	// No acknowledgement: the caller must be told it is unconfirmed, not that
	// the reload succeeded.
	h := NewMaintenanceHandlers(db, cfg)
	h.reloadAckTimeout = 200 * time.Millisecond
	w := httptest.NewRecorder()
	h.ReloadConfig(w, httptest.NewRequest("POST", "/api/maintenance/reload-config", nil))
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] == "success" {
		t.Error("reported success with no acknowledgement from the proxy")
	}

	// A payload in the shape the REAL producer emits. The Python watchdog builds
	// this with json.dump, and the fixture below is a byte-for-byte capture of
	// that output — not a Go struct marshalled back, which is what the writeAck
	// helper does. That distinction is the whole point: json.Marshal from an
	// int64 emits an integer, so a Go-built fixture exercises the decoder against
	// the one shape it cannot disagree with, and passed for the entire life of a
	// mechanism that never worked in production (SECURE-TEST-01, SECURE-API-01).
	t.Run("decodes the payload the Python watchdog actually writes", func(t *testing.T) {
		var res reloadResult
		if err := json.Unmarshal([]byte(
			`{"trigger_mtime": 1788937285, "generator_rc": 0, "reconfigure_rc": 0, "applied": true, "at": 1788937286}`,
		), &res); err != nil {
			t.Fatalf("the watchdog's acknowledgement did not decode: %v", err)
		}
		if !res.Applied || res.TriggerMtime != 1788937285 {
			t.Errorf("decoded wrong: applied=%v trigger_mtime=%d", res.Applied, res.TriggerMtime)
		}
		// And the shape that broke it: a float, which is what os.path.getmtime
		// produced before the watchdog started writing int(). If this ever
		// decodes cleanly the guard below is no longer needed; if it does not,
		// the producer must keep emitting an integer.
		var bad reloadResult
		if err := json.Unmarshal([]byte(`{"trigger_mtime": 1788937285.959049}`), &bad); err == nil {
			t.Error("a float trigger_mtime decoded into int64 — the producer-side int() is no longer load-bearing, update this test")
		}
	})

	// A watchdog that applied it.
	stamp := time.Now().Unix() + 1
	writeAck := func(applied bool) {
		res := map[string]any{
			"trigger_mtime": stamp, "generator_rc": 0, "reconfigure_rc": 0, "applied": applied, "at": stamp,
		}
		if !applied {
			res["generator_rc"] = 1
		}
		b, _ := json.Marshal(res)
		if err := os.WriteFile(filepath.Join(cfg.ConfigDir, ".reload-squid.result"), b, 0o644); err != nil {
			t.Fatalf("write ack: %v", err)
		}
	}

	writeAck(true)
	h2 := NewMaintenanceHandlers(db, cfg)
	h2.reloadAckTimeout = 2 * time.Second
	w2 := httptest.NewRecorder()
	h2.ReloadConfig(w2, httptest.NewRequest("POST", "/api/maintenance/reload-config", nil))
	if w2.Code != http.StatusOK {
		t.Errorf("applied reload: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	// A watchdog that refused it must NOT be reported as success.
	writeAck(false)
	w3 := httptest.NewRecorder()
	h2.ReloadConfig(w3, httptest.NewRequest("POST", "/api/maintenance/reload-config", nil))
	if w3.Code == http.StatusOK {
		var r3 map[string]any
		_ = json.NewDecoder(w3.Body).Decode(&r3)
		if r3["status"] == "success" {
			t.Error("a refused reload was reported as success — the exact failure this closes")
		}
	}
}
