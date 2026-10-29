package handlers

import (
	"net/http"
	"testing"
)

// A paste on an allowed list is one source of kind paste, as a paste on a
// blocked list is. The page used to send each line to the single add, so the
// entries were recorded as Manual and the paste could not be removed whole.
func TestAPasteOnAnAllowedListIsOnePastedListSource(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)

	for _, c := range []struct{ path, table, col, content, first, second string }{
		{"/api/ip-whitelist/import", "ip_whitelist", "ip", `10.0.0.5\n# note\n\n10.0.1.0/24\n10.0.0.5`, "10.0.0.5", "10.0.1.0/24"},
		{"/api/domain-whitelist/import", "domain_whitelist", "domain", `GitHub.com\n# note\napi.github.com\ngithub.com`, "github.com", "api.github.com"},
	} {
		code, body := call(t, h, "POST", c.path, `{"content":"`+c.content+`"}`)
		if code != http.StatusOK {
			t.Fatalf("%s = %d %v", c.path, code, body)
		}
		data, _ := body["data"].(map[string]any)
		if data["added"] != float64(2) || data["skipped"] != float64(1) || data["refused"] != float64(0) {
			t.Errorf("%s data = %v, want 2 added, 1 skipped (repeated in the paste), 0 refused", c.path, data)
		}
		a, b := sourceOf(t, db, c.table, c.col, c.first), sourceOf(t, db, c.table, c.col, c.second)
		if a.kind != "paste" || a.id != b.id {
			t.Errorf("%s: sources %+v and %+v, want one pasted-list source", c.path, a, b)
		}
		// A second paste is a source of its own; a known entry stays with the first.
		if code, _ := call(t, h, "POST", c.path, `{"content":"`+c.first+`"}`); code != http.StatusOK {
			t.Fatal(code)
		}
		if again := sourceOf(t, db, c.table, c.col, c.first); again.id != a.id {
			t.Errorf("%s: %s moved to source %d", c.path, c.first, again.id.Int64)
		}
		var sources int
		_ = db.QueryRow("SELECT COUNT(*) FROM list_sources WHERE list = ?", c.table).Scan(&sources)
		if sources != 1 {
			t.Errorf("%s: %d sources after a paste that added nothing, want 1", c.path, sources)
		}
	}
}

// Each refused line is named with the reason the single add would give.
func TestAPasteOnAllowedDomainsSaysWhyEachLineIsRefused(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	code, body := call(t, h, "POST", "/api/domain-whitelist/import", `{"content":"ok.example\n.dot.example\n*.star.example\nbad name\nnot!valid"}`)
	if code != http.StatusOK {
		t.Fatalf("import = %d %v", code, body)
	}
	data, _ := body["data"].(map[string]any)
	if data["added"] != float64(1) || data["refused"] != float64(4) {
		t.Fatalf("data = %v, want 1 added and 4 refused", data)
	}
	want := map[string]string{
		".dot.example":   `".dot.example" is not an exact name: write dot.example. A domain exception takes that same name off Blocked domains, however it is written there, and covers no name under it`,
		"*.star.example": `"*.star.example" is not an exact name: write star.example. A domain exception takes that same name off Blocked domains, however it is written there, and covers no name under it`,
		"bad name":       `"bad name" is not a domain name: labels of letters, digits and hyphens separated by dots`,
		"not!valid":      `"not!valid" is not a domain name: labels of letters, digits and hyphens separated by dots`,
	}
	refusals, _ := data["refusals"].([]any)
	if len(refusals) != len(want) {
		t.Fatalf("refusals = %v", refusals)
	}
	for _, r := range refusals {
		m := r.(map[string]any)
		if got := m["reason"]; got != want[m["entry"].(string)] {
			t.Errorf("refusal of %q = %q, want %q", m["entry"], got, want[m["entry"].(string)])
		}
	}
}

// The single add says what is wrong in the words the page uses: the list by
// its name on screen, a wildcard or a leading dot with the name to write. The
// wildcard refusal used to claim "a parent domain covers its subdomains",
// which the export does not do.
func TestTheListRefusalsNameTheListAndTheReason(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	for _, c := range []struct{ path, body, want string }{
		{"/api/domain-whitelist", `{"domain":"github.com"}`, ""},
		{"/api/domain-whitelist", `{"domain":"GitHub.com"}`, `"github.com" is already on Domain exceptions`},
		{"/api/domain-whitelist", `{"domain":".github.com"}`, `".github.com" is not an exact name: write github.com. A domain exception takes that same name off Blocked domains, however it is written there, and covers no name under it`},
		{"/api/domain-whitelist", `{"domain":"*.github.com"}`, `"*.github.com" is not an exact name: write github.com. A domain exception takes that same name off Blocked domains, however it is written there, and covers no name under it`},
		{"/api/domain-whitelist", `{"domain":"git?hub.com"}`, `"git?hub.com" is not an exact name: wildcards and regular expressions are not supported on Domain exceptions`},
		{"/api/domain-whitelist", `{"domain":"not valid"}`, `"not valid" is not a domain name: labels of letters, digits and hyphens separated by dots`},
		{"/api/domain-blacklist", `{"domain":"ads.example"}`, ""},
		{"/api/domain-blacklist", `{"domain":"ads.example"}`, `"ads.example" is already on Blocked domains`},
		{"/api/domain-blacklist", `{"domain":"not valid"}`, `"not valid" is not a domain name: labels of letters, digits and hyphens separated by dots`},
		{"/api/ip-whitelist", `{"ip":"203.0.113.9"}`, ""},
		{"/api/ip-whitelist", `{"ip":"203.0.113.9"}`, `"203.0.113.9" is already on IP exceptions`},
		{"/api/ip-whitelist", `{"ip":"300.1.1.1"}`, `"300.1.1.1" is not an IP address or network`},
		{"/api/ip-blacklist", `{"ip":"203.0.113.9"}`, ""},
		{"/api/ip-blacklist", `{"ip":"203.0.113.9"}`, `"203.0.113.9" is already on Blocked IPs`},
	} {
		code, body := call(t, h, "POST", c.path, c.body)
		if c.want == "" {
			if code != http.StatusOK {
				t.Errorf("%s %s = %d %v, want 200", c.path, c.body, code, body)
			}
			continue
		}
		if code != http.StatusBadRequest || body["detail"] != c.want {
			t.Errorf("%s %s = %d %q, want 400 %q", c.path, c.body, code, body["detail"], c.want)
		}
	}
}
