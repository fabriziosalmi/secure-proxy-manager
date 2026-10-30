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
		if strings.Contains(strings.ToLower(s), "%u") {
			continue // %uXXXX decoding is new (TestPercentUDecoding)
		}
		if got, want := NormalizeInput(s), normalizeReference(s); got != want {
			t.Fatalf("%q: %q, reference %q", s, got, want)
		}
	}
}

// %uXXXX decodes to its code point, and the separator lookalikes the
// traversal payloads use read as separators; a traversal written with them
// is caught, and a %u that is not followed by four hex digits stays.
func TestPercentUDecoding(t *testing.T) {
	for in, want := range map[string]string{
		"..%u2216..%u2216windows":    `..\..\windows`,
		"..%uefc8..%uefc8etc/passwd": "../../etc/passwd",
		"%uff0e%uff0e%u2215etc":      "../etc",
		"..%uF025boot.ini":           `..\boot.ini`,
		"%u0041%U0042":               "AB",
		"100%u off":                  "100%u off",
		"%u12":                       "%u12",
	} {
		if got := NormalizeInput(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	e := New(Config{BlockThreshold: 10})
	if _, score := e.MatchRulesScored(NormalizeInput("/download?f=..%u2216..%u2216..%u2216windows%u2216win.ini")); score < 10 {
		t.Errorf("traversal with %%u2216 separators scores %d", score)
	}
}

// An overlong UTF-8 sequence for an ASCII character reads as the character,
// in its two to six byte forms; valid UTF-8 and broken sequences stay.
func TestOverlongUTF8Decoding(t *testing.T) {
	for in, want := range map[string]string{
		"\xc0\xae\xc0\xae/etc/passwd":                      "../etc/passwd",
		"\xe0\x80\xae\xe0\x80\xae\\etc\\issue":             `..\etc\issue`,
		"..\xf0\x80\x80\xafetc\xf0\x80\x80\xafissue":       "../etc/issue",
		"..\xf8\x80\x80\x80\xafetc":                        "../etc",
		"\xfc\x80\x80\x80\x80\xae\xfc\x80\x80\x80\x80\xae": "..",
		"caf\xc3\xa9 K":                                    "café K",
		"\xc0\xfe\xc0\xfe":                                 "\xc0\xfe\xc0\xfe",
		"\xc3\xa9":                                         "é",
	} {
		if got := NormalizeInput(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
