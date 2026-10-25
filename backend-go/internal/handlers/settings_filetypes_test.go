package handlers

import (
	"regexp"
	"strings"
	"testing"
)

// The pattern for a blocked extension, matched the way Squid matches it: a
// POSIX extended regex against the URL path WITH its query string, ignoring
// case (-i on the ACL, emulated here by lower-casing the path). A query after
// the extension used to let the download through: /x.exe?dl=1 was served
// (squid_acl_matrix_test.sh asserts the 403 on the real proxy).
func TestBlockedExtensionPatternMatchesAQueryAfterTheExtension(t *testing.T) {
	for _, ext := range []string{"exe", ".exe"} {
		pattern := blockedExtensionPattern(ext)
		if pattern != `\.exe(\?.*)?$` {
			t.Errorf("blockedExtensionPattern(%q) = %q", ext, pattern)
		}
		re, err := regexp.CompilePOSIX(pattern)
		if err != nil {
			t.Fatalf("%q is not a POSIX extended regex: %v", pattern, err)
		}
		cases := map[string]bool{
			"/x.exe":             true,
			"/a/b/X.EXE":         true,
			"/x.exe?dl=1":        true,
			"/x.Exe?dl=1&b=2":    true,
			"/x.exe?":            true,
			"/x.exe.txt":         false,
			"/x.exe.txt?y=1":     false,
			"/xexe":              false,
			"/x.exec?y=1":        false,
			"/x.exe/readme":      false,
			"/get?f=a.exe&b=2":   false,
			"/index.html?q=exe1": false,
		}
		for path, want := range cases {
			if got := re.MatchString(strings.ToLower(path)); got != want {
				t.Errorf("%q against %q: matched=%v, want %v", pattern, path, got, want)
			}
		}
	}
}
