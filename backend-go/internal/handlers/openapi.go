package handlers

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

// The OpenAPI 3.1 description of the API (GET /api/openapi.json) is built
// from the router itself, like the catalogue (CatalogueRoutes), so it cannot
// name a route that is not served or miss one that is. The descriptions come
// from routeDocs, the authentication from publicRoutes, and the scope an API
// token needs from auth.TokenAllows (x-spm-token-scope: read, write or none).
// Request and response schemas are given for the routes in routeSchemas; a
// test validates real responses against them.

// openAPIMethods are the methods an OpenAPI path item can hold.
var openAPIMethods = map[string]bool{
	"GET": true, "PUT": true, "POST": true, "DELETE": true,
	"OPTIONS": true, "HEAD": true, "PATCH": true, "TRACE": true,
}

func oaRef(name string) map[string]any { return map[string]any{"$ref": "#/components/schemas/" + name} }

func oaNullable(t string) map[string]any { return map[string]any{"type": []string{t, "null"}} }

var (
	oaStr  = map[string]any{"type": "string"}
	oaInt  = map[string]any{"type": "integer"}
	oaBool = map[string]any{"type": "boolean"}
)

// oaObject is a closed JSON object: every property listed, the required ones
// always present, nothing else. Closed so a response that grows or loses a
// field fails the schema test instead of drifting from the document.
func oaObject(props map[string]any, required ...string) map[string]any {
	o := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

// oaRequest is a request body: the properties a handler reads, the required
// ones always present. Not closed, because the handlers decode with
// encoding/json, which ignores a field it does not know; a closed request
// schema would tell a client that a request is refused when it is not.
func oaRequest(props map[string]any, required ...string) map[string]any {
	o := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

func oaStrMax(n int) map[string]any { return map[string]any{"type": "string", "maxLength": n} }

func oaList(item string) map[string]any {
	return oaObject(map[string]any{
		"status": map[string]any{"const": "success"},
		"data":   map[string]any{"type": "array", "items": oaRef(item)},
		"meta":   oaRef("ListMeta"),
		"total":  map[string]any{"type": "integer", "deprecated": true},
		"limit":  map[string]any{"type": "integer", "deprecated": true},
		"offset": map[string]any{"type": "integer", "deprecated": true},
	}, "status", "data", "meta")
}

func oaData(data map[string]any) map[string]any {
	return oaObject(map[string]any{"status": map[string]any{"const": "success"}, "data": data}, "status", "data")
}

// oaListEntry is a row of an IP or domain list: the entry column (ip or
// domain), its source when it was recorded (null otherwise) and, for the
// domain exceptions, the type.
func oaListEntry(col string, withType bool) map[string]any {
	props := map[string]any{
		"id": oaInt, col: oaStr,
		"description": oaNullable("string"), "added_date": oaNullable("string"),
		"source_id": oaNullable("integer"), "source_kind": oaNullable("string"),
		"source": oaNullable("string"), "source_label": oaNullable("string"),
	}
	required := []string{"id", col, "description", "added_date", "source_id", "source_kind", "source", "source_label"}
	if withType {
		props["type"] = map[string]any{"enum": []string{"fqdn"}}
		required = append(required, "type")
	}
	return oaObject(props, required...)
}

var openAPISchemas = map[string]any{
	"Error": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"status": map[string]any{"const": "error"},
			"detail": oaStr,
			"code":   oaStr,
			"errors": map[string]any{"type": "object", "additionalProperties": oaStr},
		},
		"required": []string{"status", "detail"},
	},
	"Message": map[string]any{
		"type":       "object",
		"properties": map[string]any{"status": map[string]any{"const": "success"}, "message": oaStr},
		"required":   []string{"status", "message"},
	},
	"ClientSetup": oaData(oaObject(map[string]any{
		"proxy_ip":   oaStr,
		"proxy_auth": oaBool,
		"inspection": map[string]any{"enum": []string{"bump", "peek", "off"}},
		"ca": map[string]any{"oneOf": []any{
			map[string]any{"type": "null"},
			oaObject(map[string]any{"sha256": oaStr, "not_after": oaStr}, "sha256", "not_after"),
		}},
	}, "proxy_ip", "proxy_auth", "inspection", "ca")),
	"ListMeta": oaObject(map[string]any{"total": oaInt, "limit": oaInt, "offset": oaInt, "internal": oaInt}, "total", "limit", "offset"),

	"IPEntry":         oaListEntry("ip", false),
	"DomainEntry":     oaListEntry("domain", false),
	"DomainException": oaListEntry("domain", true),
	"EgressEntry": oaObject(map[string]any{
		"id": oaInt, "entry": oaStr, "type": map[string]any{"enum": []string{"cidr", "domain"}},
		"description": oaNullable("string"), "added_date": oaNullable("string"),
	}, "id", "entry", "type", "description", "added_date"),
	"IPEntryList":         oaList("IPEntry"),
	"DomainEntryList":     oaList("DomainEntry"),
	"DomainExceptionList": oaList("DomainException"),
	"EgressEntryList":     oaList("EgressEntry"),
	"NewIPEntry":          oaRequest(map[string]any{"ip": oaStrMax(50), "description": oaStrMax(500)}, "ip"),
	"NewDomainEntry":      oaRequest(map[string]any{"domain": oaStrMax(253), "description": oaStrMax(500)}, "domain"),
	"NewEgressEntry": oaRequest(map[string]any{
		"entry": oaStrMax(253), "description": oaStrMax(500),
		"include_subdomains": map[string]any{"type": "boolean", "description": "a domain and every name under it"},
	}, "entry"),
	"BulkDelete": oaRequest(map[string]any{
		"ids": map[string]any{"type": "array", "items": oaInt, "minItems": 1, "maxItems": 1000},
	}, "ids"),
	"SourceScope": oaRequest(map[string]any{
		"scope": map[string]any{"enum": []string{"global", "groups"}, "description": "global: every client; groups: only the client groups that use it"},
	}, "scope"),
	"ImportAllowed": oaRequest(map[string]any{"content": map[string]any{"type": "string", "maxLength": 1048576, "description": "one entry per line"}}, "content"),
	"ImportBlacklist": func() map[string]any {
		o := oaRequest(map[string]any{
			"type":    map[string]any{"enum": []string{"ip", "domain"}},
			"url":     map[string]any{"type": "string", "maxLength": 2048, "description": "a list to download"},
			"content": map[string]any{"type": "string", "maxLength": 52428800, "description": "a pasted list, one entry per line"},
			"name":    map[string]any{"type": "string", "maxLength": 100, "description": "what the source is called"},
		}, "type")
		o["anyOf"] = []any{map[string]any{"required": []string{"url"}}, map[string]any{"required": []string{"content"}}}
		return o
	}(),
	"EgressProviderURL": oaRequest(map[string]any{
		"url":   map[string]any{"type": "string", "description": "an http or https URL of a list of networks, on a public address"},
		"label": map[string]any{"type": "string", "minLength": 1, "maxLength": 100, "description": "the list's name; not a catalog provider's"},
	}, "url", "label"),
	"EgressProviderSet": oaRequest(map[string]any{
		"enabled":        oaBool,
		"confirm_shared": map[string]any{"type": "boolean", "description": "required to enable a provider whose network other people's workloads share"},
	}, "enabled"),
	"ImportGeo": oaRequest(map[string]any{
		"countries": map[string]any{"type": "array", "items": oaStr, "minItems": 1, "maxItems": 50, "description": "ISO 3166-1 alpha-2 codes"},
	}, "countries"),

	// A secret is write-only: its row says whether a value is stored, never
	// the value.
	"Setting": oaObject(map[string]any{
		"setting_name": oaStr, "setting_value": oaStr,
		"secret": oaBool, "is_set": oaBool, "decrypt_failed": oaBool,
	}, "setting_name"),
	"SettingList": oaData(map[string]any{"type": "array", "items": oaRef("Setting")}),
	"SettingsUpdate": map[string]any{
		"type": "object", "additionalProperties": oaStr,
		"description": "Setting names and their new values, all as strings; a secret sent empty keeps its stored value (see ?clear=)",
	},
	"SettingsUpdated": oaObject(map[string]any{
		"status": map[string]any{"const": "success"}, "message": oaStr,
		"data": oaObject(map[string]any{"kept": map[string]any{"type": "array", "items": oaStr}}, "kept"),
	}, "status", "message", "data"),
	"SettingValue": oaObject(map[string]any{"value": oaStr}, "value"),

	"LogRow": oaObject(map[string]any{
		"id": oaInt, "timestamp": oaStr, "source_ip": oaStr, "method": oaStr, "destination": oaStr,
		"status": oaStr, "bytes": oaInt, "blocked": oaBool, "reason": oaStr, "reason_label": oaStr,
		"internal": oaBool, "kind": oaStr, "resolved_ip": oaNullable("string"), "event_id": oaNullable("string"),
	}, "id", "timestamp", "source_ip", "method", "destination", "status", "bytes", "blocked",
		"reason", "reason_label", "internal", "kind", "resolved_ip", "event_id"),
	"LogList": oaList("LogRow"),
	"LogStats": oaData(oaObject(map[string]any{
		"total_count": oaInt, "blocked_count": oaInt, "ip_blocks_count": oaInt, "last_import": oaStr,
		"blocked_by_reason": map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
	}, "total_count", "blocked_count", "ip_blocks_count", "last_import", "blocked_by_reason")),
}

// routeSchema is what a route takes and gives: the component of its request
// body, or noBody when it reads none, the query parameters it reads, and the
// component of its 200 answer. Every write operation says one or the other
// (TestEveryWriteSaysWhatItReads): a client, the command first, builds its
// arguments from this, and "not described" must not read as "takes nothing".
type routeSchema struct {
	request, response string
	noBody            bool
	query             []oaParam
}

// oaParam is a query parameter an operation reads.
type oaParam struct {
	name     string
	schema   map[string]any
	required bool
	desc     string
}

var routeSchemas = map[string]routeSchema{
	"GET /api/ip-blacklist":             {response: "IPEntryList"},
	"POST /api/ip-blacklist":            {request: "NewIPEntry", response: "Message"},
	"DELETE /api/ip-blacklist/{id}":     {response: "Message", noBody: true},
	"GET /api/ip-whitelist":             {response: "IPEntryList"},
	"POST /api/ip-whitelist":            {request: "NewIPEntry", response: "Message"},
	"DELETE /api/ip-whitelist/{id}":     {response: "Message", noBody: true},
	"GET /api/domain-blacklist":         {response: "DomainEntryList"},
	"POST /api/domain-blacklist":        {request: "NewDomainEntry", response: "Message"},
	"DELETE /api/domain-blacklist/{id}": {response: "Message", noBody: true},
	"GET /api/domain-whitelist":         {response: "DomainExceptionList"},
	"POST /api/domain-whitelist":        {request: "NewDomainEntry", response: "Message"},
	"DELETE /api/domain-whitelist/{id}": {response: "Message", noBody: true},
	"GET /api/egress-allowlist":         {response: "EgressEntryList"},
	"POST /api/egress-allowlist":        {request: "NewEgressEntry", response: "Message"},
	"GET /api/settings":                 {response: "SettingList"},
	"GET /api/client-setup":             {response: "ClientSetup"},
	"POST /api/settings":                {request: "SettingsUpdate", response: "SettingsUpdated"},
	"PUT /api/settings/{name}":          {request: "SettingValue", response: "Message"},
	"GET /api/logs":                     {response: "LogList"},
	"GET /api/logs/stats":               {response: "LogStats"},

	// The lists: what each write reads.
	"POST /api/ip-blacklist/bulk-delete":           {request: "BulkDelete"},
	"POST /api/ip-whitelist/bulk-delete":           {request: "BulkDelete"},
	"POST /api/domain-blacklist/bulk-delete":       {request: "BulkDelete"},
	"POST /api/domain-whitelist/bulk-delete":       {request: "BulkDelete"},
	"POST /api/egress-allowlist/bulk-delete":       {request: "BulkDelete"},
	"DELETE /api/ip-blacklist/clear-all":           {noBody: true},
	"DELETE /api/ip-whitelist/clear-all":           {noBody: true},
	"DELETE /api/domain-blacklist/clear-all":       {noBody: true},
	"DELETE /api/domain-whitelist/clear-all":       {noBody: true},
	"DELETE /api/egress-allowlist/clear-all":       {noBody: true},
	"DELETE /api/egress-allowlist/{id}":            {noBody: true},
	"DELETE /api/ip-blacklist/sources/{id}":        {noBody: true},
	"DELETE /api/ip-whitelist/sources/{id}":        {noBody: true},
	"DELETE /api/domain-blacklist/sources/{id}":    {noBody: true},
	"DELETE /api/domain-whitelist/sources/{id}":    {noBody: true},
	"PUT /api/ip-blacklist/sources/{id}/scope":     {request: "SourceScope"},
	"PUT /api/domain-blacklist/sources/{id}/scope": {request: "SourceScope"},
	"POST /api/domain-blacklist/presets/{preset}":  {noBody: true},
	"POST /api/domain-whitelist/presets/{preset}":  {noBody: true},
	"POST /api/ip-whitelist/import":                {request: "ImportAllowed"},
	"POST /api/domain-whitelist/import":            {request: "ImportAllowed"},
	"POST /api/blacklists/import":                  {request: "ImportBlacklist"},
	"POST /api/blacklists/import-geo":              {request: "ImportGeo"},

	// Egress provider lists.
	"POST /api/egress-providers/url":               {request: "EgressProviderURL"},
	"DELETE /api/egress-providers/url/{id}":        {noBody: true},
	"PUT /api/egress-providers/{name}":             {request: "EgressProviderSet"},
	"POST /api/egress-providers/{name}/refresh":    {noBody: true},
	"POST /api/egress-providers/{name}/apply-held": {noBody: true},
}

// chiParam matches a path parameter, with chi's optional regexp ({id:[0-9]+}).
var chiParam = regexp.MustCompile(`\{([^}:]+)(:[^}]*)?\}`)

// tokenScope is the scope an API token needs for method on route: read,
// write, or none when no token may call it.
func tokenScope(method, route string) string {
	switch {
	case auth.TokenAllows("read", method, route):
		return "read"
	case auth.TokenAllows("write", method, route):
		return "write"
	}
	return "none"
}

func operationID(method, path string) string {
	id := strings.ToLower(method) + strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_", ".", "_").Replace(path)
	return strings.TrimSuffix(id, "_")
}

// OpenAPIDocument describes every route registered on r that an OpenAPI path
// item can hold (CONNECT cannot).
func OpenAPIDocument(r chi.Router) map[string]any {
	paths := map[string]any{}
	for _, d := range CatalogueRoutes(r) {
		if !openAPIMethods[d.Method] {
			continue
		}
		path := chiParam.ReplaceAllString(d.Path, "{$1}")
		item, _ := paths[path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[path] = item
		}
		key := d.Method + " " + d.Path
		op := map[string]any{
			"operationId": operationID(d.Method, path),
			"summary":     d.Desc,
			"tags":        []string{tagOf(path)},
		}
		var params []any
		for _, m := range chiParam.FindAllStringSubmatch(d.Path, -1) {
			params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": oaStr})
		}
		ok := map[string]any{"description": "Success"}
		s := routeSchemas[key]
		if s.response != "" {
			ok["content"] = map[string]any{"application/json": map[string]any{"schema": oaRef(s.response)}}
		}
		if s.request != "" {
			op["requestBody"] = map[string]any{
				"required": true,
				"content":  map[string]any{"application/json": map[string]any{"schema": oaRef(s.request)}},
			}
		}
		if s.noBody {
			// Said, not left out: a client can tell "takes nothing" from "not described".
			op["x-spm-body"] = "none"
		}
		for _, q := range s.query {
			p := map[string]any{"name": q.name, "in": "query", "required": q.required, "schema": q.schema}
			if q.desc != "" {
				p["description"] = q.desc
			}
			params = append(params, p)
		}
		if params != nil {
			op["parameters"] = params
		}
		errResp := func(desc string) map[string]any {
			return map[string]any{"description": desc, "content": map[string]any{"application/json": map[string]any{"schema": oaRef("Error")}}}
		}
		responses := map[string]any{"200": ok}
		if d.Auth {
			responses["401"] = errResp("No valid credential")
			responses["403"] = errResp("An API token whose scope does not allow this call")
			op["x-spm-token-scope"] = tokenScope(d.Method, d.Path)
		} else {
			// No credential the middleware checks; the WebSocket checks its
			// own single-use token (GET /api/ws-token).
			op["security"] = []any{}
		}
		op["responses"] = responses
		surf := routeSurfaces[d.Method+" "+path]
		op["x-spm-surfaces"] = surf.names()
		if surf.apiOnly != "" {
			op["x-spm-api-only"] = surf.apiOnly
		}
		if surf.notInUI != "" {
			op["x-spm-not-in-ui"] = surf.notInUI
		}
		item[strings.ToLower(d.Method)] = op
	}
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "Secure Proxy Manager API",
			"version":     config.APIVersion,
			"description": "The management API of Secure Proxy Manager. x-spm-token-scope on an operation is the scope an API token needs to call it: read, write, or none when no token may. x-spm-surfaces names where the operation can be reached: api, and ui, cli and mcp when the dashboard, the spm command or the MCP server offer it; x-spm-api-only, when present, is why only the API offers it, and x-spm-not-in-ui why the dashboard does not.",
			"license":     map[string]any{"name": "MIT", "identifier": "MIT"},
		},
		"servers": []any{map[string]any{"url": "/", "description": "The dashboard host (https://<host>:8443), or the backend from its host (http://127.0.0.1:5001)"}},
		"security": []any{
			map[string]any{"basicAuth": []string{}},
			map[string]any{"bearerAuth": []string{}},
			map[string]any{"cookieAuth": []string{}},
		},
		"paths": paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"basicAuth":  map[string]any{"type": "http", "scheme": "basic", "description": "The admin username and password"},
				"bearerAuth": map[string]any{"type": "http", "scheme": "bearer", "description": "An access token from POST /api/auth/login, or an API token (spm_<id>_<secret>)"},
				"cookieAuth": map[string]any{"type": "apiKey", "in": "cookie", "name": auth.SessionCookieName, "description": "The dashboard's session; a state-changing request also needs X-Requested-With: spm"},
			},
			"schemas": openAPISchemas,
		},
	}
}

// tagOf groups operations by the first path segment after /api.
func tagOf(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 1 && parts[0] == "api" {
		return parts[1]
	}
	return parts[0]
}

// registerOpenAPI serves the document, behind authentication like /api/docs:
// it is a map of the API, the unauthenticated part included.
func registerOpenAPI(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, OpenAPIDocument(r))
	})
}
