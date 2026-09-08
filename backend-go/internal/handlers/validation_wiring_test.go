package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
)

// SECURE-DOM-02. internal/models declared 20 `validate:` constraints and no
// validator was registered anywhere in the module, so every one of them was a
// comment. The semantic rules were duplicated by hand in the handlers, but the
// LENGTH bounds were not enforced at all: a description tagged max=500 took
// anything up to the 55MB body cap and wrote it into SQLite.
//
// These post to the real routes through the real router. The finding is that
// the tags were not WIRED, so a test that calls validate.Struct directly would
// pass with the handlers untouched.
func TestDeclaredBoundsAreEnforcedOnTheWire(t *testing.T) {
	r := buildFullRouter(t)

	post := func(path string, body any) (int, string) {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}

	long := func(n int) string { return strings.Repeat("a", n) }

	cases := []struct {
		name string
		path string
		body any
		// The tag being exercised, for the failure message.
		tag string
	}{
		{"ip description over max=500", "/api/ip-blacklist",
			models.IPListItem{IP: "203.0.113.4", Description: long(501)}, "IPListItem.description max=500"},
		{"whitelist description over max=500", "/api/ip-whitelist",
			models.IPListItem{IP: "203.0.113.5", Description: long(501)}, "IPListItem.description max=500"},
		{"domain over max=253", "/api/domain-blacklist",
			models.DomainListItem{Domain: long(254) + ".test", Description: "x"}, "DomainListItem.domain max=253"},
		{"domain description over max=500", "/api/domain-blacklist",
			models.DomainListItem{Domain: "example.test", Description: long(501)}, "DomainListItem.description max=500"},
		{"egress entry over max=253", "/api/egress-allowlist",
			models.EgressAllowItem{Entry: long(254)}, "EgressAllowItem.entry max=253"},
		{"import type not in oneof", "/api/blacklists/import",
			models.ImportBlacklistRequest{Type: "regex", Content: "x"}, "ImportBlacklistRequest.type oneof=ip domain"},
		{"import url over max=2048", "/api/blacklists/import",
			models.ImportBlacklistRequest{Type: "ip", URL: "https://example.test/" + long(2048)}, "ImportBlacklistRequest.url max=2048"},
		{"geo countries over max=50", "/api/blacklists/import-geo",
			models.ImportGeoBlacklistRequest{Countries: make([]string, 51)}, "ImportGeoBlacklistRequest.countries max=50"},
		{"geo countries below min=1", "/api/blacklists/import-geo",
			models.ImportGeoBlacklistRequest{Countries: []string{}}, "ImportGeoBlacklistRequest.countries min=1"},
		{"bulk delete with no ids", "/api/ip-blacklist/bulk-delete",
			models.BulkDeleteRequest{IDs: nil}, "BulkDeleteRequest.ids required"},
		{"login password over max=128", "/api/auth/login",
			models.LoginRequest{Username: "admin", Password: long(129)}, "LoginRequest.password max=128"},
		{"login username over max=128", "/api/auth/login",
			models.LoginRequest{Username: long(129), Password: "x"}, "LoginRequest.username max=128"},
		{"alert with no event_type", "/api/internal/alert",
			models.InternalAlert{Message: "m"}, "InternalAlert.event_type required"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := post(tc.path, tc.body)
			if code != http.StatusBadRequest {
				t.Errorf("%s was accepted: got %d %s, want 400", tc.tag, code, strings.TrimSpace(body))
			}
		})
	}
}

// ChangePassword sits behind the real auth middleware, so it is driven
// directly with an authenticated context rather than through the router above.
func TestChangePasswordEnforcesDeclaredMinimum(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewAuthHandlers(db, svc, cfg, nil, nil)

	// 7 characters: one under min=8, and otherwise strong enough that the
	// regex checks after the validator would not be what rejects it.
	body, _ := json.Marshal(models.ChangePasswordRequest{
		CurrentPassword: "admin-12345",
		NewPassword:     "Sh0rt!x",
	})
	req := withUserContext(httptest.NewRequest(http.MethodPost, "/api/change-password", bytes.NewReader(body)), "admin")
	rec := httptest.NewRecorder()
	h.ChangePassword(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a 7-character password was accepted against min=8: %d %s", rec.Code, rec.Body.String())
	}

	// An 8-character passphrase is at the limit and must be accepted. This one
	// is multi-byte on purpose: the policy is written in characters, and
	// validate measures strings in runes (TestStringBoundsCountRunes pins that
	// semantics — here it only has to not be rejected).
	body, _ = json.Marshal(models.ChangePasswordRequest{
		CurrentPassword: "admin-12345",
		NewPassword:     "Пароль1!",
	})
	req = withUserContext(httptest.NewRequest(http.MethodPost, "/api/change-password", bytes.NewReader(body)), "admin")
	rec = httptest.NewRecorder()
	h.ChangePassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("an 8-character multi-byte passphrase was rejected: %d %s", rec.Code, rec.Body.String())
	}
}

// A value at the declared limit must still be accepted — an off-by-one in the
// comparison would otherwise reject exactly the input the tag permits, and
// every assertion above would still pass.
func TestValuesAtTheDeclaredLimitAreAccepted(t *testing.T) {
	r := buildFullRouter(t)
	item := models.IPListItem{IP: "203.0.113.9", Description: strings.Repeat("a", 500)}
	b, _ := json.Marshal(item)
	req := httptest.NewRequest("POST", "/api/ip-blacklist", bytes.NewReader(b))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("a 500-character description (max=500) was rejected: %d %s", w.Code, strings.TrimSpace(w.Body.String()))
	}
}

// maxGeoCountries is a hand-written mirror of the tag on the model. Assert they
// agree, so the constant cannot drift away from the rule it claims to mirror.
func TestMaxGeoCountriesMatchesTheTag(t *testing.T) {
	f, ok := reflect.TypeOf(models.ImportGeoBlacklistRequest{}).FieldByName("Countries")
	if !ok {
		t.Fatal("Countries field is gone")
	}
	want := "max=" + itoa(maxGeoCountries)
	if !strings.Contains(f.Tag.Get("validate"), want) {
		t.Errorf("maxGeoCountries=%d but the tag is %q, expected it to contain %q",
			maxGeoCountries, f.Tag.Get("validate"), want)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
