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
			if s.apiOnly != "" && (s.ui || s.cli || s.mcp) {
				t.Errorf("%s is api-only (%s) and also on %v", key, s.apiOnly, s.names())
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
