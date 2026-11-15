package handlers

import (
	"sort"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/cli"
)

// The operations the registry marks cli are exactly the ones the spm
// command's curated commands call (internal/cli/commands.go), both ways, as
// the UI and MCP surfaces are held to their callers. spm api reaches every
// operation; cli marks those with a command of their own.
func TestTheCommandCallsExactlyTheOperationsMarkedCli(t *testing.T) {
	called := map[string]bool{}
	for _, k := range cli.CommandOperations() {
		called[k] = true
		s, ok := routeSurfaces[k]
		if !ok {
			t.Errorf("a command calls %s, which is not an operation", k)
			continue
		}
		if !s.cli {
			t.Errorf("a command calls %s, which surfaces.go does not mark cli", k)
		}
	}
	var marked []string
	for k, s := range routeSurfaces {
		if s.cli && !called[k] {
			marked = append(marked, k)
		}
	}
	sort.Strings(marked)
	for _, k := range marked {
		t.Errorf("surfaces.go marks %s cli, and no command calls it", k)
	}
	if len(called) < 30 {
		t.Fatalf("only %d operations from the command table: the test would prove little", len(called))
	}
}
