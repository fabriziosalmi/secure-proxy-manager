package workers

import (
	"database/sql"
	"testing"
)

// The upstream address Squid connected to, from the %Sh/%<a field: an IP in
// canonical form, or empty when Squid connected nowhere or names a host.
func TestExtractResolvedIP(t *testing.T) {
	for _, tc := range []struct{ hier, want string }{
		{"HIER_DIRECT/213.160.98.161", "213.160.98.161"},
		{"HIER_DIRECT/2a0b:f4c0:1c00:0001::abcd", "2a0b:f4c0:1c00:1::abcd"},
		{"HIER_DIRECT/::ffff:198.51.100.7", "198.51.100.7"},
		{"ORIGINAL_DST/[2001:db8::1]", "2001:db8::1"},
		{"HIER_NONE/-", ""},
		{"HIER_DIRECT/0.0.0.0", ""},
		{"HIER_DIRECT/::", ""},
		{"FIRSTUP_PARENT/parent.example", ""},
		{"HIER_DIRECT/", ""},
		{"HIER_DIRECT", ""},
		{"-", ""},
		{"HIER_DIRECT/999.1.1.1", ""},
	} {
		if got := extractResolvedIP(tc.hier); got != tc.want {
			t.Errorf("extractResolvedIP(%q) = %q, want %q", tc.hier, got, tc.want)
		}
	}
}

func TestParseSquidLineRecordsTheUpstreamAddress(t *testing.T) {
	if got := parseSquidLine(lineAllowed); got["resolved_ip"] != "192.168.88.20" {
		t.Errorf("allowed request: resolved_ip = %v, want 192.168.88.20", got["resolved_ip"])
	}
	if got := parseSquidLine(lineDomainBL); got["resolved_ip"] != "" {
		t.Errorf("denied request (HIER_NONE): resolved_ip = %v, want empty", got["resolved_ip"])
	}
}

// Stored as the address, and NULL when there is none, so "not known" stays
// apart from any value.
func TestInsertLogBatchStoresTheUpstreamAddress(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	batch := []map[string]any{parseSquidLine(lineAllowed), parseSquidLine(lineDomainBL), {"source_ip": "1.2.3.4"}}
	if err := insertLogBatch(db, batch); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query("SELECT resolved_ip FROM proxy_logs ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []sql.NullString
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		got = append(got, v)
	}
	if len(got) != 3 || got[0].String != "192.168.88.20" || got[1].Valid || got[2].Valid {
		t.Fatalf("stored resolved_ip = %v, want [192.168.88.20 NULL NULL]", got)
	}
}
