package cli

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
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
	// DryRun: the operation declares ?dry_run, so true answers what it would
	// do and changes nothing. A server that does not declare it ignores the
	// parameter and runs the call.
	DryRun bool
}

var operations = func() []operation {
	ops, err := parseOperations(openAPIDocument)
	if err != nil {
		panic("the embedded OpenAPI document does not parse: " + err.Error())
	}
	return ops
}()

// parseOperations reads the operations of an OpenAPI document: the embedded
// one, or the one a server publishes.
func parseOperations(document []byte) ([]operation, error) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(document, &doc); err != nil {
		return nil, err
	}
	var ops []operation
	for path, item := range doc.Paths {
		for method, raw := range item {
			var op struct {
				Summary     string         `json:"summary"`
				Scope       string         `json:"x-spm-token-scope"`
				APIOnly     string         `json:"x-spm-api-only"`
				Body        string         `json:"x-spm-body"`
				RequestBody map[string]any `json:"requestBody"`
				Parameters  []struct {
					Name string `json:"name"`
					In   string `json:"in"`
				} `json:"parameters"`
			}
			if json.Unmarshal(raw, &op) != nil {
				continue // a path item's "parameters" or "summary", not an operation
			}
			dry := false
			for _, p := range op.Parameters {
				dry = dry || p.Name == "dry_run" && p.In == "query"
			}
			ops = append(ops, operation{
				Method: strings.ToUpper(method), Path: path, Summary: op.Summary, Scope: op.Scope,
				APIOnly: op.APIOnly, ReadsNoBody: op.Body == "none", HasBody: op.RequestBody != nil,
				DryRun: dry,
			})
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Path != ops[j].Path {
			return ops[i].Path < ops[j].Path
		}
		return ops[i].Method < ops[j].Method
	})
	return ops, nil
}

// findOperation is the operation a method and a concrete path (its query left
// out) call: /api/ip-blacklist/42 is DELETE /api/ip-blacklist/{id}. A literal
// segment wins over a parameter, so /api/ip-blacklist/clear-all is not {id}.
func findOperation(method, path string) (operation, bool) {
	return findIn(operations, method, path)
}

func findIn(operations []operation, method, path string) (operation, bool) {
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

// asksDryRun says whether a path's query asks for a preview: a dry_run that is
// not empty or false. A server that declares the parameter answers true with a
// preview and refuses any other value; one that does not ignores it and runs
// the call, which is why such a request is checked first (serverPreviews).
func asksDryRun(path string) bool {
	_, query, _ := strings.Cut(path, "?")
	q, err := url.ParseQuery(query)
	if err != nil {
		return strings.Contains(query, "dry_run")
	}
	for _, v := range q["dry_run"] {
		if v != "" && v != "false" {
			return true
		}
	}
	return false
}

// serverPreviews says whether the server cl talks to declares ?dry_run on the
// operation method and path call, reading the OpenAPI document it publishes:
// the command's own copy may be newer than the server.
func serverPreviews(cl *client, method, path string) (bool, error) {
	r, err := cl.do("GET", "/api/openapi.json", nil)
	if err != nil {
		return false, err
	}
	if r.status != 200 {
		return false, fmt.Errorf("GET /api/openapi.json answered %d", r.status)
	}
	ops, err := parseOperations(r.body)
	if err != nil {
		return false, fmt.Errorf("the server's OpenAPI document does not parse: %w", err)
	}
	op, ok := findIn(ops, method, path)
	return ok && op.DryRun, nil
}
