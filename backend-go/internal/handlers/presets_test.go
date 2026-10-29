package handlers

import (
	"encoding/json"
	"testing"
)

// One click on "+ Docker" used to be five POSTs from the page: five entries
// with the source "Manual", five audit rows, and no way to tell the preset's
// entries from typed ones. The preset endpoint adds them in one request,
// under a source of their own, with one audit event.
func TestPresetAddsItsDomainsUnderItsOwnSourceWithOneAuditEvent(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)

	// One Docker domain typed by hand first: it keeps its manual source.
	if code, out := call(t, h, "POST", "/api/domain-whitelist", `{"domain":"hub.docker.com"}`); code != 200 {
		t.Fatalf("manual add: %d %v", code, out)
	}
	var auditBefore int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&auditBefore)

	code, out := call(t, h, "POST", "/api/domain-whitelist/presets/docker", "")
	if code != 200 {
		t.Fatalf("preset add: %d %v", code, out)
	}
	data, _ := out["data"].(map[string]any)
	if added, _ := data["added"].([]any); len(added) != 4 {
		t.Errorf("added = %v, want the 4 Docker domains not yet listed", data["added"])
	}
	if data["already"] != float64(1) {
		t.Errorf("already = %v, want 1 (hub.docker.com)", data["already"])
	}

	var presetSources, presetEntries, manualEntries int
	_ = db.QueryRow("SELECT COUNT(*) FROM list_sources WHERE list='domain_whitelist' AND kind='preset' AND source='docker' AND label='Common services: Docker'").Scan(&presetSources)
	_ = db.QueryRow("SELECT COUNT(*) FROM domain_whitelist w JOIN list_sources s ON s.id = w.source_id WHERE s.kind='preset'").Scan(&presetEntries)
	_ = db.QueryRow("SELECT COUNT(*) FROM domain_whitelist w JOIN list_sources s ON s.id = w.source_id WHERE s.kind='manual'").Scan(&manualEntries)
	if presetSources != 1 || presetEntries != 4 || manualEntries != 1 {
		t.Errorf("preset sources %d, preset entries %d, manual entries %d; want 1, 4, 1", presetSources, presetEntries, manualEntries)
	}

	var auditAfter int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&auditAfter)
	if auditAfter-auditBefore != 1 {
		t.Errorf("%d audit rows for one preset, want 1", auditAfter-auditBefore)
	}
	var action, target, details string
	_ = db.QueryRow("SELECT action, target, details FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&action, &target, &details)
	var d map[string]any
	_ = json.Unmarshal([]byte(details), &d)
	if action != "add_preset_domain_whitelist" || target != "Docker" || d["added"] != float64(4) || d["already"] != float64(1) {
		t.Errorf("audit = %s %s %s", action, target, details)
	}

	// Removing the preset's source leaves the typed entry.
	var sid int
	_ = db.QueryRow("SELECT id FROM list_sources WHERE kind='preset'").Scan(&sid)
	if code, out := call(t, h, "DELETE", "/api/domain-whitelist/sources/"+itoa(sid), ""); code != 200 {
		t.Fatalf("remove preset source: %d %v", code, out)
	}
	var left int
	_ = db.QueryRow("SELECT COUNT(*) FROM domain_whitelist").Scan(&left)
	if left != 1 {
		t.Errorf("%d entries after removing the preset, want the 1 typed by hand", left)
	}
}

// The list of presets says which domains each already has on the list,
// whatever source added them, so the page can show the state before a click.
func TestPresetListSaysWhatIsAlreadyListed(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	if code, _ := call(t, h, "POST", "/api/domain-blacklist", `{"domain":"dns.google"}`); code != 200 {
		t.Fatal("seed")
	}
	code, out := call(t, h, "GET", "/api/domain-blacklist/presets", "")
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	list, _ := out["data"].([]any)
	if len(list) != 1 {
		t.Fatalf("presets = %v", out["data"])
	}
	p := list[0].(map[string]any)
	domains, _ := p["domains"].([]any)
	listed, _ := p["listed"].([]any)
	if p["id"] != "doh" || len(domains) != 14 || len(listed) != 1 || listed[0] != "dns.google" {
		t.Errorf("doh preset = %v", p)
	}
}

func TestPresetUnknownIsNotFound(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	if code, _ := call(t, listRouter(t, db, cfg), "POST", "/api/domain-whitelist/presets/nope", ""); code != 404 {
		t.Errorf("unknown preset: %d, want 404", code)
	}
}
