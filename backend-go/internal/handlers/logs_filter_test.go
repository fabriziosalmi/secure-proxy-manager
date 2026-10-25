package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type logsPage struct {
	Data []struct {
		ID          int64  `json:"id"`
		SourceIP    string `json:"source_ip"`
		Method      string `json:"method"`
		Destination string `json:"destination"`
		Blocked     bool   `json:"blocked"`
		Reason      string `json:"reason"`
		ReasonLabel string `json:"reason_label"`
		Internal    bool   `json:"internal"`
		Kind        string `json:"kind"`
	} `json:"data"`
	Meta struct {
		Total    int  `json:"total"`
		Internal *int `json:"internal"`
	} `json:"meta"`
}

func getLogs(t *testing.T, h *LogHandlers, query string) (logsPage, int) {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/logs?"+query, nil)
	w := httptest.NewRecorder()
	h.GetLogs(w, r)
	var p logsPage
	if w.Code == http.StatusOK {
		if err := json.NewDecoder(w.Body).Decode(&p); err != nil {
			t.Fatalf("decode %q: %v", query, err)
		}
	}
	return p, w.Code
}

func (p logsPage) sources() map[string]int {
	out := map[string]int{}
	for _, r := range p.Data {
		out[r.SourceIP]++
	}
	return out
}

// seedInternalFixture (internal_sources_test.go): 8 rows from two LAN
// devices, 16 from the stack (the Docker host 5, the backend 6, loopback 2,
// the proxy's DNS rows 3).
func filterFixture(t *testing.T) (*LogHandlers, func()) {
	t.Helper()
	db, _, _, cleanup := setupTestDB(t)
	seedInternalFixture(t, db)
	return NewLogHandlers(db).WithSources(composeSources(t, db)), cleanup
}

// The access log used to list every row: the backend's own fetches, the
// Docker host and loopback filled the page a person opens to see what their
// devices did. The default now leaves the internal sources out and says how
// many rows it left out.
func TestLogsLeaveInternalSourcesOutByDefault(t *testing.T) {
	h, cleanup := filterFixture(t)
	defer cleanup()

	p, code := getLogs(t, h, "limit=100")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if got := p.sources(); len(got) != 2 || got[lanClient] != 5 || got[lan172] != 3 {
		t.Errorf("default view sources = %v, want only %s (5) and %s (3)", got, lanClient, lan172)
	}
	if p.Meta.Total != 8 {
		t.Errorf("meta.total = %d, want 8", p.Meta.Total)
	}
	if p.Meta.Internal == nil || *p.Meta.Internal != 16 {
		t.Errorf("meta.internal = %v, want 16 hidden rows", p.Meta.Internal)
	}
	for _, r := range p.Data {
		if r.Internal {
			t.Errorf("row %d from %s is internal in the default view", r.ID, r.SourceIP)
		}
		if r.Kind != "Private network address" {
			t.Errorf("row %d from %s: kind %q, want the classifier's", r.ID, r.SourceIP, r.Kind)
		}
	}

	all, _ := getLogs(t, h, "limit=100&include_internal=true")
	if all.Meta.Total != 24 || len(all.Data) != 24 {
		t.Errorf("include_internal: total %d, rows %d; want 24 and 24", all.Meta.Total, len(all.Data))
	}
	if all.Meta.Internal != nil {
		t.Errorf("include_internal: meta.internal = %d, want absent (nothing is hidden)", *all.Meta.Internal)
	}
	kinds := map[string]string{}
	for _, r := range all.Data {
		if r.Internal {
			kinds[r.SourceIP] = r.Kind
		}
	}
	if kinds[backendIP] != "Internal: the backend" || kinds[hostGateway] != "Internal: this host" {
		t.Errorf("internal kinds = %v", kinds)
	}
}

// A client named by source_ip is listed whatever it is: "Show this client's
// requests" from an internal address on the Clients page must not come back
// empty because the default leaves internal sources out.
func TestLogsSourceFilterIsExactAndNamesAnInternalSourceToo(t *testing.T) {
	h, cleanup := filterFixture(t)
	defer cleanup()

	p, _ := getLogs(t, h, "source_ip="+lanClient)
	if got := p.sources(); len(got) != 1 || got[lanClient] != 5 || p.Meta.Total != 5 {
		t.Errorf("source_ip=%s: sources %v total %d", lanClient, got, p.Meta.Total)
	}
	// Exact: a prefix of an address is not the address.
	if p, _ := getLogs(t, h, "source_ip=192.168.0.10"); len(p.Data) != 0 {
		t.Errorf("source_ip=192.168.0.10 matched %v", p.sources())
	}
	p, _ = getLogs(t, h, "source_ip="+backendIP)
	if len(p.Data) != 6 || p.Meta.Total != 6 || p.Meta.Internal != nil {
		t.Errorf("source_ip=%s (internal): rows %d total %d internal %v; want 6, 6, absent", backendIP, len(p.Data), p.Meta.Total, p.Meta.Internal)
	}
}

func TestLogsOutcomeAndRuleFilters(t *testing.T) {
	h, cleanup := filterFixture(t)
	defer cleanup()

	blocked, _ := getLogs(t, h, "outcome=blocked")
	if blocked.Meta.Total != 3 || len(blocked.Data) != 3 {
		t.Errorf("outcome=blocked: total %d rows %d, want 3 (waf, unclassified, ip_blacklist)", blocked.Meta.Total, len(blocked.Data))
	}
	for _, r := range blocked.Data {
		if !r.Blocked {
			t.Errorf("outcome=blocked returned allowed row %d", r.ID)
		}
	}
	if blocked.Meta.Internal == nil || *blocked.Meta.Internal != 3 {
		t.Errorf("outcome=blocked: meta.internal = %v, want 3 (the Docker host's domain_blacklist rows)", blocked.Meta.Internal)
	}

	allowed, _ := getLogs(t, h, "outcome=allowed")
	if allowed.Meta.Total != 5 || len(allowed.Data) != 5 {
		t.Errorf("outcome=allowed: total %d rows %d, want 5", allowed.Meta.Total, len(allowed.Data))
	}
	for _, r := range allowed.Data {
		if r.Blocked {
			t.Errorf("outcome=allowed returned blocked row %d", r.ID)
		}
	}
	if allowed.Meta.Internal == nil || *allowed.Meta.Internal != 13 {
		t.Errorf("outcome=allowed: meta.internal = %v, want 13", allowed.Meta.Internal)
	}

	waf, _ := getLogs(t, h, "reason=waf")
	if len(waf.Data) != 1 || waf.Data[0].Reason != "waf" || waf.Data[0].ReasonLabel != "WAF" || waf.Meta.Total != 1 {
		t.Errorf("reason=waf: %+v total %d", waf.Data, waf.Meta.Total)
	}
	dom, _ := getLogs(t, h, "reason=domain_blacklist&include_internal=true")
	if dom.Meta.Total != 3 {
		t.Errorf("reason=domain_blacklist with internal: total %d, want 3", dom.Meta.Total)
	}
	// The rule filter selects what a rule blocked: "none" names no rule.
	if none, _ := getLogs(t, h, "reason=none&include_internal=true"); len(none.Data) != 0 {
		t.Errorf("reason=none matched %d rows", len(none.Data))
	}
}

// q is a substring of the destination, bound as a LIKE pattern with % and _
// escaped: a search for "50%" is not "anything after 50".
func TestLogsDestinationSearchIsALiteralSubstring(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	now := time.Now()
	for _, d := range []string{"http://shop.test/50%off", "http://shop.test/50xoff", "http://a_b.test/", "http://axb.test/", "http://EXAMPLE.test/"} {
		insertLogRow(t, db, now, lanClient, "GET", d, 0, "none")
	}
	h := NewLogHandlers(db)
	cases := map[string][]string{
		"50%":     {"http://shop.test/50%off"},
		"a_b":     {"http://a_b.test/"},
		"example": {"http://EXAMPLE.test/"},
		"'; DROP": {},
	}
	for q, want := range cases {
		p, code := getLogs(t, h, "q="+strings.NewReplacer("%", "%25", " ", "%20", ";", "%3B", "'", "%27").Replace(q))
		if code != http.StatusOK {
			t.Fatalf("q=%q: status %d", q, code)
		}
		var got []string
		for _, r := range p.Data {
			got = append(got, r.Destination)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") || p.Meta.Total != len(want) {
			t.Errorf("q=%q: got %v (total %d), want %v", q, got, p.Meta.Total, want)
		}
	}
}

// before_id pages back through the log in id order; the pages neither
// overlap nor skip a row.
func TestLogsCursorPagesOlderRows(t *testing.T) {
	h, cleanup := filterFixture(t)
	defer cleanup()
	seen := map[int64]bool{}
	var order []int64
	q := "limit=3&include_internal=true"
	for i := 0; i < 20; i++ {
		p, code := getLogs(t, h, q)
		if code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		for _, r := range p.Data {
			if seen[r.ID] {
				t.Fatalf("row %d returned twice", r.ID)
			}
			seen[r.ID] = true
			order = append(order, r.ID)
		}
		if len(p.Data) < 3 {
			break
		}
		q = fmt.Sprintf("limit=3&include_internal=true&before_id=%d", p.Data[len(p.Data)-1].ID)
	}
	if len(order) != 24 {
		t.Fatalf("paged %d rows, want 24", len(order))
	}
	for i := 1; i < len(order); i++ {
		if order[i] >= order[i-1] {
			t.Fatalf("ids not descending at %d: %v", i, order)
		}
	}
}

func TestLogsRejectMalformedFilters(t *testing.T) {
	h, cleanup := filterFixture(t)
	defer cleanup()
	for _, q := range []string{
		"outcome=denied",
		"reason=WAF",
		"reason=waf%27--",
		"include_internal=yes",
		"before_id=0",
		"before_id=abc",
		"source_ip=" + strings.Repeat("1", 65),
		"q=" + strings.Repeat("x", 257),
	} {
		if _, code := getLogs(t, h, q); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, code)
		}
	}
	// Existing callers' parameters keep working.
	if p, code := getLogs(t, h, "limit=10&offset=2&sort=timestamp&order=asc&include_internal=true"); code != http.StatusOK || len(p.Data) != 10 {
		t.Errorf("limit/offset/sort: status %d rows %d", code, len(p.Data))
	}
}

// countLogs counts "not internal" and "allowed" as differences. Every filter
// combination's total must equal a direct COUNT over the same condition.
func TestLogCountsEqualTheDirectCount(t *testing.T) {
	h, cleanup := filterFixture(t)
	defer cleanup()
	internal := h.src.Present()
	for _, f := range []logFilter{
		{}, {includeInternal: true},
		{outcome: "allowed"}, {outcome: "allowed", includeInternal: true},
		{outcome: "blocked"}, {reason: "domain_blacklist"}, {reason: "domain_blacklist", includeInternal: true},
		{q: "test"}, {q: "host-only", outcome: "allowed"}, {sourceIP: hostGateway, outcome: "allowed"},
	} {
		w, a := f.where(internal, false)
		var direct int
		if err := h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE "+w, a...).Scan(&direct); err != nil {
			t.Fatal(err)
		}
		total, hidden, err := countLogs(h.db, f, internal)
		if err != nil {
			t.Fatal(err)
		}
		if total != direct {
			t.Errorf("%+v: countLogs total %d, direct count %d", f, total, direct)
		}
		if f.hidesInternal() {
			g := f
			g.includeInternal = true
			gw, ga := g.where(internal, false)
			var withInternal int
			_ = h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE "+gw, ga...).Scan(&withInternal)
			if hidden == nil || *hidden != withInternal-direct {
				t.Errorf("%+v: hidden %v, want %d", f, hidden, withInternal-direct)
			}
		}
	}
}
