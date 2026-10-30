package crs

import (
	"io/fs"
	"math/rand"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	re2 "github.com/wasilibs/go-re2"

	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/regexsample"
)

// rxPatterns are the arguments of every @rx operator in the rule set, as
// Coraza reads them: the quoted operator, with \" unescaped.
func rxPatterns(t *testing.T) []string {
	t.Helper()
	op := regexp.MustCompile(`"@rx ((?:[^"\\]|\\.)*)"`)
	var out []string
	err := fs.WalkDir(coreruleset.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".conf") {
			return err
		}
		b, err := fs.ReadFile(coreruleset.FS, path)
		if err != nil {
			return err
		}
		for _, m := range op.FindAllStringSubmatch(string(b), -1) {
			out = append(out, strings.ReplaceAll(m[1], `\"`, `"`))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The RE2 rx operator agrees with Coraza's on the rule set's own patterns:
// the same verdict as Go's regexp on strings drawn from each pattern, near
// misses and stray bytes that are not valid UTF-8 included, the value given
// to RE2 as Go reads it.
func TestRXAgreesWithCorazas(t *testing.T) {
	pats := rxPatterns(t)
	if len(pats) < 200 {
		t.Fatalf("only %d @rx patterns found in the rule set", len(pats))
	}
	r := rand.New(rand.NewSource(5))
	checked := 0
	for _, p := range pats {
		data := "(?sm)" + p
		if matchesArbitraryBytes(data) {
			continue // the binary matcher, as Coraza
		}
		goRe, err := regexp.Compile(data)
		if err != nil {
			continue // Coraza refuses it too
		}
		re, err := re2.Compile(data)
		if err != nil {
			t.Errorf("RE2 does not compile %q: %v", p, err)
			continue
		}
		parsed, err := syntax.Parse(data, syntax.Perl)
		if err != nil {
			continue
		}
		parsed = parsed.Simplify()
		checked++
		for i := 0; i < 300; i++ {
			var b strings.Builder
			regexsample.Draw(parsed, r, &b)
			s := "x " + b.String() + " y"
			switch {
			case i%3 == 2 && len(s) > 2: // a near miss
				k := r.Intn(len(s))
				s = s[:k] + s[k+1:]
			case i%3 == 1: // a byte, or half a character, that is not valid UTF-8
				k := r.Intn(len(s) + 1)
				s = s[:k] + []string{"\xff", "\xe2\x84", "\xc5"}[r.Intn(3)] + s[k:]
			}
			if g, e := goRe.MatchString(s), re.MatchString(engine.AsRE2Input(s)); g != e {
				t.Errorf("%.80q on %.120q: Go %v, RE2 %v", p, s, g, e)
				break
			}
		}
	}
	t.Logf("%d of %d @rx patterns checked", checked, len(pats))
}

// fakeTx is the part of a transaction an operator uses.
type fakeTx struct {
	plugintypes.TransactionState
	capturing bool
	caps      map[int]string
}

func (f *fakeTx) Capturing() bool { return f.capturing }
func (f *fakeTx) CaptureField(i int, v string) {
	if f.caps == nil {
		f.caps = map[int]string{}
	}
	f.caps[i] = v
}

// A byte that is not valid UTF-8 matches . and [^...] as in Coraza's own
// operator, captured or not: a stray byte inside an attack does not let it
// through. A pattern spelling arbitrary bytes goes to the binary matcher.
func TestRXReadsInvalidBytesAsGo(t *testing.T) {
	for _, c := range []struct {
		pattern, value string
		want           bool
	}{
		{`a.b`, "a\xffb", true},
		{`<!ENTITY\s+\S+\s+SYSTEM`, "<!ENTITY \xff SYSTEM", true},
		{`a[^x]{2}b`, "a\xe2\x84b", true},
		{`^\xff$`, "\xff", true},
		{`a.b`, "ab", false},
	} {
		op, err := newRX(plugintypes.OperatorOptions{Arguments: c.pattern})
		if err != nil {
			t.Fatalf("%s: %v", c.pattern, err)
		}
		for _, capturing := range []bool{false, true} {
			tx := &fakeTx{capturing: capturing}
			if got := op.Evaluate(tx, c.value); got != c.want {
				t.Errorf("%s on %q (capturing %v): %v, want %v", c.pattern, c.value, capturing, got, c.want)
			}
		}
	}
	tx := &fakeTx{capturing: true}
	op, _ := newRX(plugintypes.OperatorOptions{Arguments: `(\w+)=(\d+)`})
	if !op.Evaluate(tx, "x id=42 y") || tx.caps[0] != "id=42" || tx.caps[1] != "id" || tx.caps[2] != "42" {
		t.Errorf("captures %v", tx.caps)
	}
}

func shadowCount(name string) uint64 {
	_, byRule := engine.ShadowStats()
	for _, r := range byRule {
		if r.Rule == name {
			return r.Count
		}
	}
	return 0
}

// With go in force and the shadow on, rx answers with Go's regexp, captures
// included, and a different RE2 answer is counted under the pattern's name.
func TestRXShadowKeepsGoAndCountsRE2(t *testing.T) {
	restore := engine.SetRegexForTest("go", true)
	defer restore()
	op, err := newRX(plugintypes.OperatorOptions{Arguments: `sh(adow)-test-(\d+)`})
	if err != nil {
		t.Fatal(err)
	}
	rx := op.(*rxRE2)
	saved := rx.re
	rx.re = re2.MustCompile(`\A\z never`)
	defer func() { rx.re = saved }()
	before := shadowCount(rx.shadowName)
	tx := &fakeTx{capturing: true}
	if !op.Evaluate(tx, "a shadow-test-42 b") || tx.caps[2] != "42" {
		t.Errorf("go in force: no match or captures %v", tx.caps)
	}
	if !op.Evaluate(&fakeTx{}, "shadow-test-7") {
		t.Error("go in force: no match without capturing")
	}
	if got := shadowCount(rx.shadowName) - before; got != 2 {
		t.Errorf("%d disagreements counted under %s, want 2", got, rx.shadowName)
	}
}
