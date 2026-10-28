package database

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sqlTextBuilders are the only functions that may convert to SQLText: they
// build text from a count and from other SQLText, never from a value.
var sqlTextBuilders = map[string]bool{"Placeholders": true, "JoinSQL": true}

// driverMethods take the statement text as an argument: the first, or the
// second after a context.
var driverMethods = map[string]int{
	"Query": 0, "QueryRow": 0, "Exec": 0, "Prepare": 0,
	"QueryContext": 1, "QueryRowContext": 1, "ExecContext": 1, "PrepareContext": 1,
}

// sqlGuardViolations parses every non-test Go file under the backend and
// reports, as file:line: what, each place that could put a value into SQL
// text: an explicit SQLText conversion outside the builders, and a
// concatenation handed straight to a database/sql call. Statement text is
// built as SQLText (constants, placeholders, other SQLText) and converted
// with string(...) at the call.
//
// What it cannot see without type information: string("..." + s) around a
// concatenation of plain strings passes, as it is a conversion and not a
// bare concatenation. Writing that is a deliberate act, visible in review;
// the type and this test stop the accidental case.
func sqlGuardViolations(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					if fun.Name == "SQLText" && (fn == nil || !sqlTextBuilders[fn.Name.Name]) {
						out = append(out, fset.Position(call.Pos()).String()+": SQLText(...) conversion")
					}
				case *ast.SelectorExpr:
					if fun.Sel.Name == "SQLText" {
						out = append(out, fset.Position(call.Pos()).String()+": SQLText(...) conversion")
					}
					if i, ok := driverMethods[fun.Sel.Name]; ok && len(call.Args) > i {
						if _, concat := call.Args[i].(*ast.BinaryExpr); concat {
							out = append(out, fset.Position(call.Args[i].Pos()).String()+": concatenation passed to "+fun.Sel.Name)
						}
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func TestNoValueCanReachSQLText(t *testing.T) {
	if v := sqlGuardViolations(t, filepath.Join("..", "..")); len(v) > 0 {
		t.Fatalf("SQL text built outside SQLText (%d):\n%s", len(v), strings.Join(v, "\n"))
	}
}
