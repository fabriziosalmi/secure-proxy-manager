package main

import (
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// noDashes are the em and en dash, which the project's user-facing text must
// not contain (scripts/check-no-dashes.sh covers the docs and the UI).
const noDashes = "\u2014\u2013"

// stringsWithDashes reports every string literal of the Go files under root,
// test files excluded, that holds an em or en dash. It reads STRING tokens with
// go/scanner, so comments, runes and identifiers never match, and a raw string
// spanning several lines is one token.
func stringsWithDashesIn(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- walking this module's own source tree
		if err != nil {
			return err
		}
		file := fset.AddFile(path, fset.Base(), len(src))
		var s scanner.Scanner
		s.Init(file, src, nil, 0) // comments are skipped
		for {
			pos, tok, lit := s.Scan()
			if tok == token.EOF {
				break
			}
			if tok == token.STRING && strings.ContainsAny(lit, noDashes) {
				found = append(found, fset.Position(pos).String())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// A message the API returns, a log line or an error must not carry an em or
// en dash; comments may.
func TestNoDashInWAFStringLiterals(t *testing.T) {
	if found := stringsWithDashesIn(t, "."); len(found) > 0 {
		t.Errorf("string literals with an em or en dash:\n  %s", strings.Join(found, "\n  "))
	}
}

// The scanner sees a dash in a string, a raw string over several lines, and
// none in a comment or a rune: the check would catch a regression and does not
// flag what it must not.
func TestTheWAFDashCheckReadsOnlyStrings(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package p\n\n// a comment \u2014 fine\nvar r = '\"'\nvar s = \"plain\" // trailing \"quoted\" \u2014 comment\n")
	if found := stringsWithDashesIn(t, dir); len(found) != 0 {
		t.Fatalf("flagged a comment or a rune: %v", found)
	}
	write("b.go", "package p\n\nvar x = \"a \u2014 b\"\nvar y = `line one\nline \u2013 two`\n")
	write("b_test.go", "package p\n\nvar z = \"test \u2014 ok\"\n")
	if found := stringsWithDashesIn(t, dir); len(found) != 2 {
		t.Fatalf("found %d, want the two literals in b.go: %v", len(found), found)
	}
}
