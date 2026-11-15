package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// requestPending lists the write operations whose request is not described
// yet. It may only shrink: an operation described since must leave it, and a
// new write operation must be described, not added here.
var requestPending = map[string]bool{}

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
// parameters ({source} is a source the seed made), a body valid by its schema
// ({feed} is the fake provider feed's address), and what to set up first.
// Each call runs on a fresh database with entries on every list.
type requestCase struct {
	path  string
	body  string
	setup func(t *testing.T, r http.Handler, feed *fakeProviderFeedServer)
	// asAdmin signs the request in with the test admin's password, for a route
	// the auth service guards itself (it is not given the test's pass-through).
	asAdmin bool
}

// aLogTarget saves a log forwarding target, a UDP socket on loopback.
func aLogTarget(t *testing.T, r http.Handler, _ *fakeProviderFeedServer) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	if code, out := call(t, r, "POST", "/api/settings", `{"log_forward_host":"127.0.0.1","log_forward_port":"`+port+`"}`); code != http.StatusOK {
		t.Fatalf("save a log target: %d %v", code, out)
	}
}

// aGroup makes client group 1.
func aGroup(t *testing.T, r http.Handler, _ *fakeProviderFeedServer) {
	t.Helper()
	if code, out := call(t, r, "POST", "/api/client-groups", `{"name":"g1","members":["10.0.1.0/24"]}`); code != http.StatusOK {
		t.Fatalf("make group 1: %d %v", code, out)
	}
}

// aSnapshot takes configuration snapshot 1.
func aSnapshot(t *testing.T, r http.Handler, _ *fakeProviderFeedServer) {
	t.Helper()
	if code, out := call(t, r, "POST", "/api/config/snapshots", `{}`); code != http.StatusOK {
		t.Fatalf("take snapshot 1: %d %v", code, out)
	}
}

// checkedElsewhere names the operations whose request is validated by
// another service: the backend passes the body on, so only that service can
// say a field is missing. Each names the test that holds it to its schema.
var checkedElsewhere = map[string]string{
	"POST /api/waf/categories/toggle": "the WAF reads it: waf-go TestTheToggleRequestMatchesThePublishedSchema",
}

// heldUpdate leaves the facebook provider with a held update: enabled at
// 1000 addresses, then a feed that grew by more than 25%.
func heldUpdate(t *testing.T, r http.Handler, feed *fakeProviderFeedServer) {
	t.Helper()
	feed.mu.Lock()
	feed.sha = "d03d319a255c0000000000000000000000000020"
	feed.mu.Unlock()
	feed.setCatalog("facebook", buildExactIPv4List(1000), "")
	if code, out := call(t, r, "PUT", "/api/egress-providers/facebook", `{"enabled":true}`); code != http.StatusOK {
		t.Fatalf("enable facebook: %d %v", code, out)
	}
	feed.mu.Lock()
	feed.sha = "d03d319a255c0000000000000000000000000021"
	feed.mu.Unlock()
	feed.setCatalog("facebook", buildExactIPv4List(1300), "")
	if code, out := call(t, r, "POST", "/api/egress-providers/facebook/refresh", ""); code != http.StatusOK {
		t.Fatalf("refresh facebook: %d %v", code, out)
	}
}

// refused is whether a status says the request itself was refused: 400 for
// a malformed one, 422 for one the WAF (or the backend in its place) cannot
// take.
func refused(code int) bool {
	return code == http.StatusBadRequest || code == http.StatusUnprocessableEntity
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

	"POST /api/egress-providers/url":               {path: "/api/egress-providers/url", body: `{"url":"{feed}/custom.txt","label":"partner-feed"}`},
	"DELETE /api/egress-providers/url/{id}":        {path: "/api/egress-providers/url/1"},
	"PUT /api/egress-providers/{name}":             {path: "/api/egress-providers/telegram", body: `{"enabled":true}`},
	"POST /api/egress-providers/{name}/refresh":    {path: "/api/egress-providers/telegram/refresh"},
	"POST /api/egress-providers/{name}/apply-held": {path: "/api/egress-providers/facebook/apply-held", setup: heldUpdate},

	"PUT /api/waf/policy":                     {path: "/api/waf/policy", body: `{"policy":{"version":1,"mode":"observe"},"sha256":""}`},
	"POST /api/waf/policy/exceptions":         {path: "/api/waf/policy/exceptions", body: `{"rule":"942100","host":"app.example.com","comment":"x"}`},
	"POST /api/waf/policy/observe-rules":      {path: "/api/waf/policy/observe-rules", body: `{"rule":"942100"}`},
	"POST /api/waf/categories/toggle":         {path: "/api/waf/categories/toggle", body: `{"category":"SQLI","enabled":false}`},
	"POST /api/waf/test-rule":                 {path: "/api/waf/test-rule", body: `{"regex":"example","hours":24}`},
	"POST /api/config/snapshots":              {path: "/api/config/snapshots", body: `{"note":"before the move"}`},
	"POST /api/config/snapshots/{id}/restore": {path: "/api/config/snapshots/1/restore", setup: aSnapshot},
	"POST /api/client-groups":                 {path: "/api/client-groups", body: `{"name":"office","members":["10.0.0.0/24"],"schedule":{"days":"MTWHF","start":"08:00","end":"18:00"}}`},
	"PUT /api/client-groups/{id}":             {path: "/api/client-groups/1", body: `{"name":"office2","members":["10.0.0.0/24"],"schedule":null}`, setup: aGroup},
	"DELETE /api/client-groups/{id}":          {path: "/api/client-groups/1", setup: aGroup},

	"POST /api/auth/login":                  {path: "/api/auth/login", body: `{"username":"admin","password":"admin-12345"}`},
	"POST /api/logout":                      {path: "/api/logout", asAdmin: true},
	"POST /api/change-password":             {path: "/api/change-password", body: `{"current_password":"admin-12345","new_password":"N3w-passw0rd!"}`, asAdmin: true},
	"POST /api/tokens":                      {path: "/api/tokens", body: `{"name":"grafana","scope":"read","expires_in_days":30}`},
	"DELETE /api/tokens/{id}":               {path: "/api/tokens/1"},
	"DELETE /api/security/rate-limits/{ip}": {path: "/api/security/rate-limits/192.0.2.7"},
	"POST /api/dns/detect":                  {path: "/api/dns/detect", body: `{"subnet":"127.0.0"}`},
	"POST /api/maintenance/restore-config":  {path: "/api/maintenance/restore-config", body: `{"backup_version":3,"settings":{"cache_size":"2000"}}`},
	"POST /api/maintenance/reload-config":   {path: "/api/maintenance/reload-config"},
	"POST /api/maintenance/reload-dns":      {path: "/api/maintenance/reload-dns"},
	"POST /api/maintenance/clear-cache":     {path: "/api/maintenance/clear-cache"},
	"POST /api/logs/clear":                  {path: "/api/logs/clear"},
	"POST /api/logs/clear-old":              {path: "/api/logs/clear-old?days=30"},
	"POST /api/counters/reset":              {path: "/api/counters/reset"},
	"POST /api/database/optimize":           {path: "/api/database/optimize"},
	"POST /api/database/reset":              {path: "/api/database/reset"},
	"POST /api/log-forward/test":            {path: "/api/log-forward/test", setup: aLogTarget},
	"POST /api/notifications/test":          {path: "/api/notifications/test"},
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

	// No address is probed: the DNS scan answers nothing at once.
	savedProbe := probeDNS
	probeDNS = func(string) *DetectedDNS { return nil }
	t.Cleanup(func() { probeDNS = savedProbe })
	// No watchdog answers here: the reload and cache-clear waits are cut short.
	saved := defaultAckTimeouts
	defaultAckTimeouts.reload, defaultAckTimeouts.clear = 50*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { defaultAckTimeouts = saved })
	feed, feedSrv := newFakeProviderFeedServer(t, "d03d319a255c0000000000000000000000000001")
	feed.setCatalog("telegram", "149.154.160.0/20\n", "")
	call := func(t *testing.T, c requestCase, method, path, body string) (int, string) {
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
		if c.setup != nil {
			c.setup(t, r, feed)
		}
		body = strings.ReplaceAll(body, "{feed}", feedSrv.URL)
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
		if c.asAdmin {
			req.SetBasicAuth("admin", "admin-12345")
		}
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
				if code, out := call(t, c, method, c.path, ""); code == http.StatusBadRequest {
					t.Errorf("says it reads no body, and sent none it answers 400: %s", out)
				} else if code == http.StatusUnauthorized || code == http.StatusForbidden {
					t.Errorf("answered %d before the handler reads it: the case proves nothing: %s", code, out)
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
			if code, out := call(t, c, method, c.path, c.body); refused(code) {
				t.Errorf("a body valid by %s is refused (%d): %s", name, code, out)
			} else if code == http.StatusUnauthorized || code == http.StatusForbidden {
				// The request never reached the handler: the case proves nothing.
				t.Errorf("the valid case is answered %d before the handler reads it: %s", code, out)
			}
			if why, ok := checkedElsewhere[key]; ok {
				t.Logf("required fields not checked here: %s", why)
				return
			}
			if rb := op["requestBody"].(map[string]any); rb["required"] == false {
				if code, out := call(t, c, method, c.path, ""); code == http.StatusBadRequest {
					t.Errorf("its body is optional, and sent none it answers 400: %s", out)
				}
			}
			var body map[string]any
			_ = json.Unmarshal([]byte(c.body), &body)
			component, _ := openAPISchemas[name].(map[string]any)
			// A field the schema does not know: refused (400) exactly when the
			// schema is closed, so "additionalProperties" is as true as "required".
			withExtra := map[string]any{"zz_not_a_field": 1}
			for k, v := range body {
				withExtra[k] = v
			}
			b, _ := json.Marshal(withExtra)
			// A map (additionalProperties is a schema, as for the settings) takes
			// keys by their own rules; the check is for objects with fields.
			if _, isMap := component["additionalProperties"].(map[string]any); !isMap {
				closed := component["additionalProperties"] == false
				if code, out := call(t, c, method, c.path, string(b)); closed && !refused(code) {
					t.Errorf("%s is closed, and a field it does not know is answered %d, want it refused: %s", name, code, out)
				} else if !closed && refused(code) {
					t.Errorf("%s is open, and a field it does not know is refused (%d): %s", name, code, out)
				}
			}
			required, _ := component["required"].([]string)
			for _, field := range required {
				without := map[string]any{}
				for k, v := range body {
					if k != field {
						without[k] = v
					}
				}
				b, _ := json.Marshal(without)
				if code, out := call(t, c, method, c.path, string(b)); !refused(code) {
					t.Errorf("without %s, which %s requires, it answers %d, want it refused (400 or 422): %s", field, name, code, out)
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
				if code, out := call(t, c, method, c.path, string(b)); !refused(code) {
					t.Errorf("with none of the fields %s needs one of, it answers %d, want it refused (400 or 422): %s", name, code, out)
				}
			}
		})
	}
}
