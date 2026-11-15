package cli

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
)

// openAPIDocument is docs/public/openapi.json as of this build. The handlers'
// TestThePublishedOpenAPIIsCurrent writes and checks this copy with the
// published one, so the command knows the operations of its own release.
//
//go:embed openapi.json
var openAPIDocument []byte

type operation struct {
	Method, Path, Summary, Scope string
	APIOnly                      string
	ReadsNoBody                  bool
	HasBody                      bool
}

var operations = func() []operation {
	var doc struct {
		Paths map[string]map[string]struct {
			Summary     string         `json:"summary"`
			Scope       string         `json:"x-spm-token-scope"`
			APIOnly     string         `json:"x-spm-api-only"`
			Body        string         `json:"x-spm-body"`
			RequestBody map[string]any `json:"requestBody"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(openAPIDocument, &doc); err != nil {
		panic("the embedded OpenAPI document does not parse: " + err.Error())
	}
	var ops []operation
	for path, item := range doc.Paths {
		for method, op := range item {
			ops = append(ops, operation{
				Method: strings.ToUpper(method), Path: path, Summary: op.Summary, Scope: op.Scope,
				APIOnly: op.APIOnly, ReadsNoBody: op.Body == "none", HasBody: op.RequestBody != nil,
			})
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Path != ops[j].Path {
			return ops[i].Path < ops[j].Path
		}
		return ops[i].Method < ops[j].Method
	})
	return ops
}()

// findOperation is the operation a method and a concrete path (its query left
// out) call: /api/ip-blacklist/42 is DELETE /api/ip-blacklist/{id}. A literal
// segment wins over a parameter, so /api/ip-blacklist/clear-all is not {id}.
func findOperation(method, path string) (operation, bool) {
	path = strings.SplitN(path, "?", 2)[0]
	want := strings.Split(strings.TrimRight(path, "/"), "/")
	best, bestParams := operation{}, -1
	for _, op := range operations {
		if op.Method != method {
			continue
		}
		have := strings.Split(op.Path, "/")
		if len(have) != len(want) {
			continue
		}
		params, ok := 0, true
		for i := range have {
			switch {
			case have[i] == want[i]:
			case strings.HasPrefix(have[i], "{") && want[i] != "":
				params++
			default:
				ok = false
			}
			if !ok {
				break
			}
		}
		if ok && (bestParams == -1 || params < bestParams) {
			best, bestParams = op, params
		}
	}
	return best, bestParams != -1
}
