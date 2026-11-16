package handlers

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every operation says where it is reached, and no entry is left over from
// an operation that is gone. A new route without an entry fails here, so a
// route cannot be added to the API and silently miss the UI, the command and
// the MCP server.
func TestEveryOperationSaysWhereItIsReached(t *testing.T) {
	doc := OpenAPIDocument(publishedRouter(t))
	seen := map[string]bool{}
	for path, item := range doc["paths"].(map[string]any) {
		for method := range item.(map[string]any) {
			key := strings.ToUpper(method) + " " + path
			seen[key] = true
			s, ok := routeSurfaces[key]
			if !ok {
				t.Errorf("%s has no entry in routeSurfaces (surfaces.go): say where it is reached, or why only the API offers it", key)
				continue
			}
			if s.apiOnly != "" && (s.ui || s.cli || s.mcp || s.notInUI != "" || s.uiPlanned) {
				t.Errorf("%s is api-only (%s) and also says more: %+v", key, s.apiOnly, s)
			}
			if s.ui && (s.notInUI != "" || s.uiPlanned) {
				t.Errorf("%s is on the UI and still marked notInUI or uiPlanned", key)
			}
			if s.notInUI != "" && s.uiPlanned {
				t.Errorf("%s is both notInUI and uiPlanned", key)
			}
			if !s.ui && s.apiOnly == "" && s.notInUI == "" && !s.uiPlanned {
				t.Errorf("%s carries no decision: mark it ui, apiOnly, notInUI or uiPlanned (surfaces.go)", key)
			}
		}
	}
	for key := range routeSurfaces {
		if !seen[key] {
			t.Errorf("routeSurfaces names %s, which is not an operation", key)
		}
	}
	if len(seen) < 100 {
		t.Fatalf("only %d operations: the document was not built from the full router", len(seen))
	}
}

// Every operation says what it does: the published document had 17 without a
// summary, which the command and the MCP server would show as nothing.
func TestEveryOperationHasASummary(t *testing.T) {
	doc := OpenAPIDocument(publishedRouter(t))
	for path, item := range doc["paths"].(map[string]any) {
		for method, op := range item.(map[string]any) {
			if s, _ := op.(map[string]any)["summary"].(string); strings.TrimSpace(s) == "" {
				t.Errorf("%s %s has no summary: describe it in routeDocs (api_docs.go)", strings.ToUpper(method), path)
			}
		}
	}
}

// The MCP server builds its tools from the published document: an operation
// marked mcp carries the tool's name, every name is one tool's, and the 13
// names the server had before it read the registry are kept, so an assistant
// configured with them keeps finding them. untrusted is said only of an MCP
// tool, the one place it changes anything.
func TestTheMCPToolsAreNamedInTheRegistry(t *testing.T) {
	nameRE := regexp.MustCompile(`^spm_[a-z][a-z_]*$`)
	byName := map[string]string{}
	for key, s := range routeSurfaces {
		if s.mcp != (s.mcpName != "") {
			t.Errorf("%s: mcp %v with mcpName %q: a tool has a name, a name is a tool's", key, s.mcp, s.mcpName)
		}
		if s.untrusted && !s.mcp {
			t.Errorf("%s is marked untrusted and is no MCP tool", key)
		}
		if s.mcpName == "" {
			continue
		}
		if !nameRE.MatchString(s.mcpName) {
			t.Errorf("%s: tool name %q is not spm_ and lower case", key, s.mcpName)
		}
		if other, dup := byName[s.mcpName]; dup {
			t.Errorf("%s and %s are both %s", key, other, s.mcpName)
		}
		byName[s.mcpName] = key
	}
	for _, name := range []string{"spm_status", "spm_dashboard", "spm_top_domains", "spm_shadow_it",
		"spm_user_agents", "spm_recent_logs", "spm_waf_categories", "spm_list_domain_blocklist",
		"spm_block_domain", "spm_unblock_domain", "spm_toggle_waf_category", "spm_allow_egress",
		"spm_reload_config"} {
		if byName[name] == "" {
			t.Errorf("the tool %s is gone: an assistant configured with it would not find it", name)
		}
	}
	doc := OpenAPIDocument(publishedRouter(t))
	published := 0
	for _, item := range doc["paths"].(map[string]any) {
		for _, op := range item.(map[string]any) {
			if n, ok := op.(map[string]any)["x-spm-mcp-name"].(string); ok && byName[n] != "" {
				published++
			}
		}
	}
	if published != len(byName) {
		t.Errorf("%d operations publish x-spm-mcp-name, want %d", published, len(byName))
	}
}

// An MCP tool a token cannot call would be offered and always refused:
// spm-mcp authenticates with a token. A reading tool needs no more than a
// read token, so the default read-only server can offer it.
func TestEveryMCPToolIsReachableWithAToken(t *testing.T) {
	for key, s := range routeSurfaces {
		if !s.mcp {
			continue
		}
		method, path, _ := strings.Cut(key, " ")
		scope := tokenScope(method, path)
		if scope == "none" {
			t.Errorf("%s (%s) is an MCP tool no token may call", key, s.mcpName)
		}
		if method == "GET" && scope != "read" {
			t.Errorf("%s (%s) reads and needs a %s token", key, s.mcpName, scope)
		}
	}
}

// These operations are kept from MCP on purpose. A read of a log row can
// carry text written to steer the model, and with these an obeyed row would
// switch off inspection, send the logs elsewhere, replace the WAF policy or
// scan the network. Offering one is a decision: remove it here with the
// reason it is now safe.
var keptFromMCP = map[string]string{
	"PUT /api/settings/{name}":                "one setting can switch off inspection or send the logs to another host",
	"POST /api/settings":                      "every setting at once",
	"POST /api/waf/policy/exceptions":         "an exception lets a request past the WAF",
	"POST /api/waf/policy/observe-rules":      "a rule left to log only stops blocking",
	"PUT /api/waf/policy":                     "replaces the whole WAF policy",
	"POST /api/config/snapshots/{id}/restore": "replaces the whole configuration",
	"DELETE /api/security/rate-limits/{ip}":   "lets an address try sign-ins again",
	"POST /api/dns/detect":                    "probes a private network from the server",
	"POST /api/database/optimize":             "locks the database while it runs",
}

func TestTheOperationsKeptFromMCPStayKept(t *testing.T) {
	for key, why := range keptFromMCP {
		s, ok := routeSurfaces[key]
		if !ok {
			t.Errorf("%s is kept from MCP and is no operation", key)
			continue
		}
		if s.mcp {
			t.Errorf("%s is an MCP tool and is kept from MCP: %s", key, why)
		}
	}
}

// mcpReadme is the spm-mcp README, whose tool table is written from the
// registry between these markers. UPDATE_OPENAPI=1 writes it.
const mcpReadme = "../../../mcp/README.md"

const mcpTableStart, mcpTableEnd = "<!-- tools:start -->\n", "<!-- tools:end -->\n"

func mcpToolTable(t *testing.T) string {
	doc := OpenAPIDocument(publishedRouter(t))
	type row struct{ name, call, offered, notes string }
	var rows []row
	for path, item := range doc["paths"].(map[string]any) {
		for method, v := range item.(map[string]any) {
			op, ok := v.(map[string]any)
			if !ok {
				continue
			}
			name, ok := op["x-spm-mcp-name"].(string)
			if !ok {
				continue
			}
			m := strings.ToUpper(method)
			offered := "always"
			if m != "GET" {
				offered = "with `SPM_MCP_READONLY=false`"
			}
			var notes []string
			if op["x-spm-untrusted"] == true {
				notes = append(notes, "untrusted")
			}
			if params, ok := op["parameters"].([]any); ok {
				for _, p := range params {
					if p.(map[string]any)["name"] == "dry_run" {
						notes = append(notes, "preview unless `confirm: true`")
					}
				}
			}
			rows = append(rows, row{name, "`" + m + " " + path + "`", offered, strings.Join(notes, ", ")})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if (rows[i].offered == "always") != (rows[j].offered == "always") {
			return rows[i].offered == "always"
		}
		return rows[i].name < rows[j].name
	})
	var b strings.Builder
	b.WriteString("| Tool | API call | Offered | Notes |\n|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", r.name, r.call, r.offered, r.notes)
	}
	return b.String()
}

func TestTheMCPToolTableIsCurrent(t *testing.T) {
	have, err := os.ReadFile(mcpReadme)
	if err != nil {
		t.Fatal(err)
	}
	before, rest, ok1 := strings.Cut(string(have), mcpTableStart)
	_, after, ok2 := strings.Cut(rest, mcpTableEnd)
	if !ok1 || !ok2 {
		t.Fatalf("%s has no %q ... %q", mcpReadme, mcpTableStart, mcpTableEnd)
	}
	want := before + mcpTableStart + mcpToolTable(t) + mcpTableEnd + after
	if os.Getenv("UPDATE_OPENAPI") == "1" {
		if err := os.WriteFile(mcpReadme, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if string(have) != want {
		t.Errorf("the tool table in %s is not the registry's; run: UPDATE_OPENAPI=1 go test ./internal/handlers -run 'TestThePublishedOpenAPIIsCurrent|TestTheMCPToolTableIsCurrent'", mcpReadme)
	}
}
