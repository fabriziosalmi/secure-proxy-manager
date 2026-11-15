package handlers

import (
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
