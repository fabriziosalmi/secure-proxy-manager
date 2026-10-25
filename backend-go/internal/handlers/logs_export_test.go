package handlers

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func readExport(t *testing.T, h *LogHandlers, query string) (*httptest.ResponseRecorder, [][]string) {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/logs/export?"+query, nil)
	w := httptest.NewRecorder()
	h.Export(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("export %q: status %d %s", query, w.Code, w.Body.String())
	}
	recs, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("export %q is not CSV: %v", query, err)
	}
	return w, recs
}

// The export holds the rows the page lists for the same filters, all of
// them, as CSV.
func TestLogsExportHasTheFilteredRows(t *testing.T) {
	h, cleanup := filterFixture(t)
	defer cleanup()
	w, recs := readExport(t, h, "outcome=blocked")
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".csv") {
		t.Errorf("Content-Disposition %q", cd)
	}
	if strings.Join(recs[0], ",") != strings.Join(exportHeader, ",") {
		t.Errorf("header %v", recs[0])
	}
	if len(recs) != 1+3 {
		t.Fatalf("outcome=blocked exported %d rows, want 3", len(recs)-1)
	}
	for _, rec := range recs[1:] {
		if rec[9] != "true" || rec[3] != "false" {
			t.Errorf("row %v: want blocked and not internal", rec)
		}
	}
	_, all := readExport(t, h, "include_internal=true")
	if len(all) != 1+24 {
		t.Errorf("include_internal exported %d rows, want 24", len(all)-1)
	}
}

// The export reads the log a page at a time; a file longer than one page has
// every row once, newest first.
func TestLogsExportCrossesPages(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	n := exportPage*2 + 7
	seed1M(t, db, n)
	h := NewLogHandlers(db)
	_, recs := readExport(t, h, "include_internal=true")
	if len(recs)-1 != n {
		t.Fatalf("exported %d rows, want %d", len(recs)-1, n)
	}
	prev := int64(1 << 62)
	for _, rec := range recs[1:] {
		var id int64
		fmt.Sscan(rec[0], &id) //nolint:errcheck
		if id >= prev {
			t.Fatalf("ids not strictly descending: %d after %d", id, prev)
		}
		prev = id
	}
}

// A cell that starts with = + - @ is a formula to a spreadsheet. The
// destination and method come from the traffic; they are written as text.
func TestLogsExportWritesFormulasAsText(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	now := time.Now()
	insertLogRow(t, db, now, lanClient, "-", `=HYPERLINK("http://evil.test","x")`, 0, "none")
	insertLogRow(t, db, now, lanClient, "GET", "+cmd", 0, "none")
	insertLogRow(t, db, now, lanClient, "GET", "@SUM(1)", 0, "none")
	insertLogRow(t, db, now, lanClient, "GET", "http://fine.test/", 0, "none")
	_, recs := readExport(t, NewLogHandlers(db), "")
	got := map[string]string{}
	for _, rec := range recs[1:] {
		got[rec[6]] = rec[5]
	}
	for _, want := range []string{`'=HYPERLINK("http://evil.test","x")`, "'+cmd", "'@SUM(1)", "http://fine.test/"} {
		if _, ok := got[want]; !ok {
			t.Errorf("destination %q not in export: %v", want, got)
		}
	}
	if got[`'=HYPERLINK("http://evil.test","x")`] != "'-" {
		t.Errorf("method \"-\" exported as %q, want '-", got[`'=HYPERLINK("http://evil.test","x")`])
	}
}

func TestLogsExportRejectsMalformedFilters(t *testing.T) {
	h, cleanup := filterFixture(t)
	defer cleanup()
	r := httptest.NewRequest("GET", "/api/logs/export?outcome=nope", nil)
	w := httptest.NewRecorder()
	h.Export(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
}
