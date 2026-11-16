package handlers

import (
	"regexp"
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
