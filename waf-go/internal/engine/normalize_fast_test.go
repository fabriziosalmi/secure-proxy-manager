package engine

import (
	"html"
	"math/rand"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// normalizeReference is NormalizeInput before its fast paths, kept to prove
// they change nothing.
func normalizeReference(input string) string {
	s := input
	for i := 0; i < 10; i++ {
		prev := s
		s = reDoubleEncode.ReplaceAllString(s, "%$1")
		s = percentDecodeTolerant(s)
		if s == prev {
			break
		}
	}
	s = html.UnescapeString(s)
	if !isASCII(s) {
		s = norm.NFKC.String(s)
	}
	if strings.Contains(s, "/*") {
		s = reBlockComment.ReplaceAllString(s, " ")
	}
	if strings.Contains(s, "<!--") {
		s = reHTMLComment.ReplaceAllString(s, " ")
	}
	s = reNullBytes.ReplaceAllString(s, "")
	s = reMultiSpace.ReplaceAllString(s, " ")
	return s
}

// The fast paths skip a regex only where it cannot match: NormalizeInput
// equals the reference on strings made of what its steps act on.
func TestNormalizeFastPathsChangeNothing(t *testing.T) {
	r := rand.New(rand.NewSource(9))
	pool := []string{"%", "25", "%25", "%00", "00", "\\x00", "\\", "x", "&", "&#0;", "&#00", "#", ";", "\x00", " ", "  ", "\t", "\n", "\r", "\f",
		"+", "/*", "*/", "<!--", "-->", "a", "Z", "é", " ", "ﬁ", "<", ">", "'", "\"", "%2", "%2525", "%u", "0"}
	for i := 0; i < 300000; i++ {
		var b strings.Builder
		for n := r.Intn(14); n > 0; n-- {
			b.WriteString(pool[r.Intn(len(pool))])
		}
		s := b.String()
		if got, want := NormalizeInput(s), normalizeReference(s); got != want {
			t.Fatalf("%q: %q, reference %q", s, got, want)
		}
	}
}
