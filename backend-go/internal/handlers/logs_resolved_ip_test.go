package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// GET /api/logs and the CSV export carry the upstream address the proxy
// connected to: the address for a request that reached a server, null (and
// an empty cell) for one that did not. It is a server's address, so GDPR
// mode leaves it as it is.
func TestLogsCarryTheUpstreamAddress(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	for _, row := range []struct {
		dest     string
		resolved any
	}{{"http://reached.test/", "203.0.113.7"}, {"http://denied.test/", nil}} {
		if _, err := db.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, blocked, block_reason, resolved_ip)
			VALUES('2026-10-28 10:00:00', 1793181600, '198.51.100.9', 'GET', ?, 'TCP_MISS/200', 10, 0, 'none', ?)`, row.dest, row.resolved); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES('gdpr_mode','true')"); err != nil {
		t.Fatal(err)
	}
	h := NewLogHandlers(db)
	w := httptest.NewRecorder()
	h.GetLogs(w, httptest.NewRequest("GET", "/api/logs?include_internal=true&sort=id&order=asc", nil))
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Data) != 2 {
		t.Fatalf("GET /api/logs: %d %s", w.Code, w.Body.String())
	}
	got := map[string]any{}
	for _, r := range body.Data {
		v, present := r["resolved_ip"]
		if !present {
			t.Fatalf("row without resolved_ip: %v", r)
		}
		got[r["destination"].(string)] = v
	}
	if got["http://reached.test/"] != "203.0.113.7" || got["http://denied.test/"] != nil {
		t.Errorf("resolved_ip on the wire = %v", got)
	}

	_, recs := readExport(t, h, "include_internal=true")
	col := -1
	for i, name := range recs[0] {
		if name == "resolved_ip" {
			col = i
		}
	}
	if col != len(recs[0])-1 {
		t.Fatalf("resolved_ip is not the last export column: %v", recs[0])
	}
	cells := map[string]string{}
	for _, rec := range recs[1:] {
		cells[rec[6]] = rec[col]
	}
	if cells["http://reached.test/"] != "203.0.113.7" || cells["http://denied.test/"] != "" {
		t.Errorf("export resolved_ip cells = %v", cells)
	}
}
