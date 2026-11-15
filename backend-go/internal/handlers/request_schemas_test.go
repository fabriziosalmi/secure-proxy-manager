package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// requestPending lists the write operations whose request is not described
// yet. It may only shrink: an operation described since must leave it, and a
// new write operation must be described, not added here.
var requestPending = map[string]bool{
	"POST /api/auth/login":                         true,
	"POST /api/change-password":                    true,
	"POST /api/client-groups":                      true,
	"DELETE /api/client-groups/{id}":               true,
	"PUT /api/client-groups/{id}":                  true,
	"POST /api/config/snapshots":                   true,
	"POST /api/config/snapshots/{id}/restore":      true,
	"POST /api/counters/reset":                     true,
	"POST /api/database/optimize":                  true,
	"POST /api/database/reset":                     true,
	"POST /api/dns/detect":                         true,
	"POST /api/egress-providers/url":               true,
	"DELETE /api/egress-providers/url/{id}":        true,
	"PUT /api/egress-providers/{name}":             true,
	"POST /api/egress-providers/{name}/apply-held": true,
	"POST /api/egress-providers/{name}/refresh":    true,
	"POST /api/log-forward/test":                   true,
	"POST /api/logout":                             true,
	"POST /api/logs/clear":                         true,
	"POST /api/logs/clear-old":                     true,
	"POST /api/maintenance/clear-cache":            true,
	"POST /api/maintenance/reload-config":          true,
	"POST /api/maintenance/reload-dns":             true,
	"POST /api/maintenance/restore-config":         true,
	"POST /api/notifications/test":                 true,
	"DELETE /api/security/rate-limits/{ip}":        true,
	"POST /api/tokens":                             true,
	"DELETE /api/tokens/{id}":                      true,
	"POST /api/waf/categories/toggle":              true,
	"PUT /api/waf/policy":                          true,
	"POST /api/waf/policy/exceptions":              true,
	"POST /api/waf/policy/observe-rules":           true,
	"POST /api/waf/test-rule":                      true,
}

// writeOperations is every operation of the published document that is not a
// GET and not api-only, with the operation object.
func writeOperations(t *testing.T) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for path, item := range OpenAPIDocument(publishedRouter(t))["paths"].(map[string]any) {
		for method, raw := range item.(map[string]any) {
			op := raw.(map[string]any)
			if method == "get" || op["x-spm-api-only"] != nil {
				continue
			}
			out[strings.ToUpper(method)+" "+path] = op
		}
	}
	return out
}

// Every write operation says what it reads: a body schema, or that it reads
// no body (x-spm-body: none). The command builds its arguments from this; an
// operation with neither would read as taking nothing when it was only not
// described.
func TestEveryWriteSaysWhatItReads(t *testing.T) {
	ops := writeOperations(t)
	if len(ops) < 60 {
		t.Fatalf("only %d write operations: the document was not built from the full router", len(ops))
	}
	for key, op := range ops {
		described := op["requestBody"] != nil || op["x-spm-body"] == "none"
		switch {
		case described && requestPending[key]:
			t.Errorf("%s is described now: take it out of requestPending", key)
		case !described && !requestPending[key]:
			t.Errorf("%s says neither its body schema nor that it reads none (routeSchemas, openapi.go)", key)
		}
		if op["requestBody"] != nil && op["x-spm-body"] != nil {
			t.Errorf("%s has a body schema and says it reads none", key)
		}
	}
	for key := range requestPending {
		if ops[key] == nil {
			t.Errorf("requestPending names %s, which is not a write operation", key)
		}
	}
}

// requestCase is how to call one write operation: the path with its
// parameters ({source} is a source the seed made) and a body valid by its
// schema. Each call runs on a fresh database with entries on every list.
type requestCase struct {
	path string
	body string
}

func seedSourceID(t *testing.T, db *sql.DB, list string) string {
	t.Helper()
	var id string
	if err := db.QueryRow("SELECT id FROM list_sources WHERE list = ? ORDER BY id LIMIT 1", list).Scan(&id); err != nil {
		t.Fatalf("no source on %s: %v", list, err)
	}
	return id
}

var requestCases = map[string]requestCase{
	"POST /api/ip-blacklist":                       {path: "/api/ip-blacklist", body: `{"ip":"203.0.113.9","description":"x"}`},
	"POST /api/ip-whitelist":                       {path: "/api/ip-whitelist", body: `{"ip":"10.0.0.9","description":"x"}`},
	"POST /api/domain-blacklist":                   {path: "/api/domain-blacklist", body: `{"domain":"ads.example.com","description":"x"}`},
	"POST /api/domain-whitelist":                   {path: "/api/domain-whitelist", body: `{"domain":"ok.example.com","description":"x"}`},
	"POST /api/egress-allowlist":                   {path: "/api/egress-allowlist", body: `{"entry":"example.com","include_subdomains":true,"description":"x"}`},
	"POST /api/settings":                           {path: "/api/settings", body: `{"cache_size":"2000"}`},
	"PUT /api/settings/{name}":                     {path: "/api/settings/cache_size", body: `{"value":"1500"}`},
	"POST /api/ip-blacklist/bulk-delete":           {path: "/api/ip-blacklist/bulk-delete", body: `{"ids":[1,2]}`},
	"POST /api/ip-whitelist/bulk-delete":           {path: "/api/ip-whitelist/bulk-delete", body: `{"ids":[1]}`},
	"POST /api/domain-blacklist/bulk-delete":       {path: "/api/domain-blacklist/bulk-delete", body: `{"ids":[1]}`},
	"POST /api/domain-whitelist/bulk-delete":       {path: "/api/domain-whitelist/bulk-delete", body: `{"ids":[1]}`},
	"POST /api/egress-allowlist/bulk-delete":       {path: "/api/egress-allowlist/bulk-delete", body: `{"ids":[1]}`},
	"PUT /api/ip-blacklist/sources/{id}/scope":     {path: "/api/ip-blacklist/sources/{source}/scope", body: `{"scope":"groups"}`},
	"PUT /api/domain-blacklist/sources/{id}/scope": {path: "/api/domain-blacklist/sources/{source}/scope", body: `{"scope":"global"}`},
	"POST /api/ip-whitelist/import":                {path: "/api/ip-whitelist/import", body: `{"content":"10.0.0.20\n10.0.0.21"}`},
	"POST /api/domain-whitelist/import":            {path: "/api/domain-whitelist/import", body: `{"content":"a.example.org\nb.example.org"}`},
	"POST /api/blacklists/import":                  {path: "/api/blacklists/import", body: `{"type":"ip","content":"203.0.113.50","name":"pasted"}`},
	"POST /api/blacklists/import-geo":              {path: "/api/blacklists/import-geo", body: `{"countries":["NL"]}`},

	// No body.
	"DELETE /api/ip-blacklist/{id}":               {path: "/api/ip-blacklist/1"},
	"DELETE /api/ip-whitelist/{id}":               {path: "/api/ip-whitelist/1"},
	"DELETE /api/domain-blacklist/{id}":           {path: "/api/domain-blacklist/1"},
	"DELETE /api/domain-whitelist/{id}":           {path: "/api/domain-whitelist/1"},
	"DELETE /api/egress-allowlist/{id}":           {path: "/api/egress-allowlist/1"},
	"DELETE /api/ip-blacklist/clear-all":          {path: "/api/ip-blacklist/clear-all"},
	"DELETE /api/ip-whitelist/clear-all":          {path: "/api/ip-whitelist/clear-all"},
	"DELETE /api/domain-blacklist/clear-all":      {path: "/api/domain-blacklist/clear-all"},
	"DELETE /api/domain-whitelist/clear-all":      {path: "/api/domain-whitelist/clear-all"},
	"DELETE /api/egress-allowlist/clear-all":      {path: "/api/egress-allowlist/clear-all"},
	"DELETE /api/ip-blacklist/sources/{id}":       {path: "/api/ip-blacklist/sources/unrecorded"},
	"DELETE /api/ip-whitelist/sources/{id}":       {path: "/api/ip-whitelist/sources/unrecorded"},
	"DELETE /api/domain-blacklist/sources/{id}":   {path: "/api/domain-blacklist/sources/unrecorded"},
	"DELETE /api/domain-whitelist/sources/{id}":   {path: "/api/domain-whitelist/sources/unrecorded"},
	"POST /api/domain-blacklist/presets/{preset}": {path: "/api/domain-blacklist/presets/doh"},
	"POST /api/domain-whitelist/presets/{preset}": {path: "/api/domain-whitelist/presets/github"},
}

// The request schemas say what the handlers accept, both ways: a body valid by
// its schema is not refused as malformed (400), and the same body without a
// field the schema requires is. An operation that says it reads no body is
// not refused when it is sent none. A schema that drifted from its handler
// would have the command build requests the API refuses, or refuse ones the
// API takes.
func TestRequestSchemasAgreeWithTheHandlers(t *testing.T) {
	ops := writeOperations(t)
	comp := compileComponents(t, OpenAPIDocument(publishedRouter(t)))

	var keys []string
	for key, op := range ops {
		if op["requestBody"] != nil || op["x-spm-body"] == "none" {
			keys = append(keys, key)
			if _, ok := requestCases[key]; !ok {
				t.Errorf("%s is described but has no case in requestCases", key)
			}
		}
	}
	sort.Strings(keys)

	call := func(t *testing.T, method, path, body string) (int, string) {
		t.Helper()
		db, svc, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		geo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("198.51.100.0/24\n")) }))
		defer geo.Close()
		cfg.GeoIPURL = geo.URL
		cfg.EncryptionKey = testEncKey
		r := buildFullRouterOn(db, svc, cfg, func(next http.Handler) http.Handler { return next })
		// Entries and a source on every list, so an id or a source names something.
		for _, q := range []struct{ path, body string }{
			{"/api/ip-blacklist", `{"ip":"203.0.113.1"}`}, {"/api/ip-blacklist", `{"ip":"203.0.113.2"}`},
			{"/api/ip-whitelist", `{"ip":"10.0.0.1"}`}, {"/api/domain-blacklist", `{"domain":"x.example"}`},
			{"/api/domain-whitelist", `{"domain":"y.example"}`}, {"/api/egress-allowlist", `{"entry":"z.example"}`},
		} {
			w := httptest.NewRecorder()
			req := withUserContext(httptest.NewRequest("POST", q.path, strings.NewReader(q.body)), "admin")
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("seed %s: %d %s", q.path, w.Code, w.Body.String())
			}
		}
		if strings.Contains(path, "{source}") {
			list := "ip_blacklist"
			if strings.Contains(path, "domain-blacklist") {
				list = "domain_blacklist"
			}
			path = strings.Replace(path, "{source}", seedSourceID(t, db, list), 1)
		}
		var rdr *strings.Reader
		if body == "" {
			rdr = strings.NewReader("")
		} else {
			rdr = strings.NewReader(body)
		}
		req := withUserContext(httptest.NewRequest(method, path, rdr), "admin")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}

	for _, key := range keys {
		c := requestCases[key]
		op := ops[key]
		method, _, _ := strings.Cut(key, " ")
		t.Run(key, func(t *testing.T) {
			if op["x-spm-body"] == "none" {
				if code, out := call(t, method, c.path, ""); code == http.StatusBadRequest {
					t.Errorf("says it reads no body, and sent none it answers 400: %s", out)
				}
				return
			}
			name := strings.TrimPrefix(op["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"].(string), "#/components/schemas/")
			sch, err := comp(name)
			if err != nil {
				t.Fatalf("compile %s: %v", name, err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(c.body)))
			if err != nil {
				t.Fatalf("the case body is not JSON: %s", c.body)
			}
			if err := sch.Validate(inst); err != nil {
				t.Fatalf("the case body does not match %s: %v", name, err)
			}
			if code, out := call(t, method, c.path, c.body); code == http.StatusBadRequest {
				t.Errorf("a body valid by %s is refused as malformed: %s", name, out)
			}
			var body map[string]any
			_ = json.Unmarshal([]byte(c.body), &body)
			component, _ := openAPISchemas[name].(map[string]any)
			required, _ := component["required"].([]string)
			for _, field := range required {
				without := map[string]any{}
				for k, v := range body {
					if k != field {
						without[k] = v
					}
				}
				b, _ := json.Marshal(without)
				if code, out := call(t, method, c.path, string(b)); code != http.StatusBadRequest {
					t.Errorf("without %s, which %s requires, it answers %d, want 400: %s", field, name, code, out)
				}
			}
			if anyOf, ok := component["anyOf"].([]any); ok {
				without := map[string]any{}
				drop := map[string]bool{}
				for _, alt := range anyOf {
					for _, f := range alt.(map[string]any)["required"].([]string) {
						drop[f] = true
					}
				}
				for k, v := range body {
					if !drop[k] {
						without[k] = v
					}
				}
				b, _ := json.Marshal(without)
				if code, out := call(t, method, c.path, string(b)); code != http.StatusBadRequest {
					t.Errorf("with none of the fields %s needs one of, it answers %d, want 400: %s", name, code, out)
				}
			}
		})
	}
}
