package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// openAPI31Schema is the official schema of OpenAPI 3.1 documents
// (https://spec.openapis.org/oas/3.1/schema/2022-10-07), kept in testdata so
// the test needs no network.
const openAPI31Schema = "https://spec.openapis.org/oas/3.1/schema/2022-10-07"

func toInstance(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

func TestOpenAPIIsAValidOpenAPI31Document(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "openapi-3.1-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(openAPI31Schema, meta); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(openAPI31Schema)
	if err != nil {
		t.Fatal(err)
	}
	doc := OpenAPIDocument(buildFullRouter(t))
	if err := sch.Validate(toInstance(t, doc)); err != nil {
		t.Fatalf("not a valid OpenAPI 3.1 document: %v", err)
	}

	// The component schemas are JSON Schema 2020-12: each compiles.
	comp := compileComponents(t, doc)
	for name := range openAPISchemas {
		if _, err := comp(name); err != nil {
			t.Errorf("components.schemas.%s: %v", name, err)
		}
	}
}

// compileComponents returns a compiler of the document's component schemas.
func compileComponents(t *testing.T, doc map[string]any) func(string) (*jsonschema.Schema, error) {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource("spm-openapi.json", toInstance(t, doc)); err != nil {
		t.Fatal(err)
	}
	return func(name string) (*jsonschema.Schema, error) {
		return c.Compile("spm-openapi.json#/components/schemas/" + name)
	}
}

func TestOpenAPINamesEveryRegisteredRouteAndNoOther(t *testing.T) {
	r := buildFullRouter(t)
	doc := OpenAPIDocument(r)
	paths := doc["paths"].(map[string]any)

	want := map[string]bool{}
	if err := chi.Walk(r.(*chi.Mux), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if openAPIMethods[method] {
			want[strings.ToLower(method)+" "+chiParam.ReplaceAllString(strings.TrimSuffix(route, "/*"), "{$1}")] = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for p, item := range paths {
		for m := range item.(map[string]any) {
			got[m+" "+p] = true
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("registered route %s is not in the document", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("the document names %s, which is not registered", k)
		}
	}
	if len(got) < 100 {
		t.Errorf("only %d operations", len(got))
	}
	t.Logf("%d operations on %d paths", len(got), len(paths))

	// Every route given a schema is a route.
	for key := range routeSchemas {
		m, p, _ := strings.Cut(key, " ")
		if !want[strings.ToLower(m)+" "+p] {
			t.Errorf("routeSchemas names %s, which is not registered", key)
		}
	}
}

func TestOpenAPISaysWhichTokenScopeEachOperationNeeds(t *testing.T) {
	paths := OpenAPIDocument(buildFullRouter(t))["paths"].(map[string]any)
	op := func(p, m string) map[string]any { return paths[p].(map[string]any)[m].(map[string]any) }
	for _, c := range []struct{ path, method, want string }{
		{"/api/settings", "get", "read"},
		{"/api/settings", "post", "write"},
		{"/api/ip-blacklist/{id}", "delete", "write"},
		{"/api/tokens", "get", "none"},
		{"/api/database/export", "get", "none"},
	} {
		if got := op(c.path, c.method)["x-spm-token-scope"]; got != c.want {
			t.Errorf("%s %s: x-spm-token-scope %v, want %s", c.method, c.path, got, c.want)
		}
	}
	login := op("/api/auth/login", "post")
	if _, has := login["x-spm-token-scope"]; has {
		t.Error("a public route carries a token scope")
	}
	if sec, ok := login["security"].([]any); !ok || len(sec) != 0 {
		t.Errorf("login security %v, want [] (no authentication)", login["security"])
	}
}

// The schemas are checked against what the handlers answer, on data that
// exercises every field: a recorded and an unrecorded source, a NULL
// description, a blocked log row with a WAF event, a secret setting.
func TestOpenAPISchemasMatchRealResponses(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey // so a secret setting can be stored
	pass := func(next http.Handler) http.Handler { return next }
	r := buildFullRouterOn(db, svc, cfg, pass)
	comp := compileComponents(t, OpenAPIDocument(r))

	for _, q := range []string{
		`INSERT INTO ip_blacklist(ip) VALUES('198.51.100.7')`,
		`INSERT INTO domain_blacklist(domain, description) VALUES('legacy.example', NULL)`,
		`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, blocked, block_reason, resolved_ip, event_id)
		   VALUES(datetime('now'), strftime('%s','now'), '10.0.0.5', 'GET', 'http://ads.example/x', 'TCP_DENIED/403', 120, 1, 'waf', NULL, 'evt-1')`,
		`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, blocked, block_reason, resolved_ip, event_id)
		   VALUES(datetime('now'), strftime('%s','now'), '10.0.0.6', 'CONNECT', 'example.com:443', 'TCP_TUNNEL/200', 5000, 0, 'none', '93.184.216.34', '')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	do := func(method, path, body string) (int, []byte) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withUserContext(req, "admin")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code, w.Body.Bytes()
	}
	check := func(key, schema string, body []byte) {
		t.Helper()
		sch, err := comp(schema)
		if err != nil {
			t.Fatalf("%s: compile %s: %v", key, schema, err)
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("%s: not JSON: %s", key, body)
		}
		if err := sch.Validate(inst); err != nil {
			t.Errorf("%s does not match %s: %v\n%s", key, schema, err, body)
		}
	}

	// Writes first, so the lists and settings read afterwards hold their rows.
	bodies := map[string]string{
		"POST /api/ip-blacklist":     `{"ip":"203.0.113.9","description":"x"}`,
		"POST /api/ip-whitelist":     `{"ip":"10.0.0.9","description":"x"}`,
		"POST /api/domain-blacklist": `{"domain":"ads.example.com","description":"x"}`,
		"POST /api/domain-whitelist": `{"domain":"ok.example.com","description":"x"}`,
		"POST /api/egress-allowlist": `{"entry":"api.example.com","description":"x"}`,
		"POST /api/settings":         `{"cache_size":"2000","gotify_token":"s3cret!"}`,
		"PUT /api/settings/{name}":   `{"value":"1500"}`,
	}
	paths := map[string]string{"PUT /api/settings/{name}": "/api/settings/cache_size"}
	order := []string{
		"POST /api/ip-blacklist", "POST /api/ip-whitelist", "POST /api/domain-blacklist",
		"POST /api/domain-whitelist", "POST /api/egress-allowlist", "POST /api/settings", "PUT /api/settings/{name}",
		"GET /api/ip-blacklist", "GET /api/ip-whitelist", "GET /api/domain-blacklist", "GET /api/domain-whitelist",
		"GET /api/egress-allowlist", "GET /api/settings", "GET /api/logs", "GET /api/logs/stats",
		"DELETE /api/ip-blacklist/{id}", "DELETE /api/ip-whitelist/{id}", "DELETE /api/domain-blacklist/{id}",
		"DELETE /api/domain-whitelist/{id}", "GET /api/client-setup",
	}
	writeTestCA(t, cfg.ConfigDir) // so the CA object, not only null, is checked
	if len(order) != len(routeSchemas) {
		t.Fatalf("the test calls %d routes, routeSchemas has %d: every route given a schema is checked", len(order), len(routeSchemas))
	}
	seen := map[string]string{}
	for _, key := range order {
		s, ok := routeSchemas[key]
		if !ok {
			t.Fatalf("%s has no schema", key)
		}
		method, path, _ := strings.Cut(key, " ")
		if p, ok := paths[key]; ok {
			path = p
		}
		path = strings.Replace(path, "{id}", "1", 1)
		if s.request != "" {
			check(key+" request", s.request, []byte(bodies[key]))
		}
		code, body := do(method, path, bodies[key])
		if code != http.StatusOK {
			t.Errorf("%s: %d %s", key, code, body)
			continue
		}
		check(key, s.response, body)
		seen[key] = string(body)
	}
	// The data reached the fields that are easy to get wrong.
	for key, want := range map[string][]string{
		"GET /api/settings":         {`"secret":true`, `"is_set":true`},
		"GET /api/logs":             {`"event_id":"evt-1"`, `"event_id":null`, `"resolved_ip":null`, `"resolved_ip":"93.184.216.34"`, `"blocked":true`},
		"GET /api/ip-blacklist":     {`"source_id":null`, `"source_kind":"manual"`},
		"GET /api/domain-blacklist": {`"description":null`},
		"GET /api/client-setup":     {`"sha256":"`},
	} {
		for _, w := range want {
			if !strings.Contains(seen[key], w) {
				t.Errorf("%s never answered %s: the schema was not tested on it", key, w)
			}
		}
	}

	// An error answer matches Error.
	_, body := do("POST", "/api/settings", `{"cache_size":"abc"}`)
	check("POST /api/settings refused", "Error", body)
}

func TestOpenAPIIsServedBehindAuthentication(t *testing.T) {
	denyAll := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	}
	r := chi.NewRouter()
	RegisterAPIDocs(r, denyAll)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/openapi.json", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/openapi.json without credentials: %d", w.Code)
	}
}

// publishedOpenAPI is the copy the documentation site serves.
const publishedOpenAPI = "../../../docs/public/openapi.json"

// The published copy is the document of the handler routes plus the two
// routes cmd/server mounts itself (mountWebSocket, /metrics); the runtime
// profiles (/debug/pprof) are left to the live document. UPDATE_OPENAPI=1
// writes it.
func TestThePublishedOpenAPIIsCurrent(t *testing.T) {
	r := buildFullRouter(t)
	stub := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	r.Get("/api/ws/logs", stub)
	r.Get("/metrics", stub)
	b, err := json.MarshalIndent(OpenAPIDocument(r), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if os.Getenv("UPDATE_OPENAPI") == "1" {
		if err := os.WriteFile(publishedOpenAPI, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(publishedOpenAPI)
	if err != nil || !bytes.Equal(have, b) {
		t.Fatalf("docs/public/openapi.json is not the generated document; run: UPDATE_OPENAPI=1 go test ./internal/handlers -run TestThePublishedOpenAPIIsCurrent (%v)", err)
	}
}
