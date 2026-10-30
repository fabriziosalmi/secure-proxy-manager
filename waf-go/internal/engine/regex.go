package engine

// The regular expression engine the matcher runs the rules with.
//
// Go's regexp has no DFA: each rule costs about 13 ns per byte of input. RE2
// itself, compiled to WebAssembly and run by wazero in pure Go
// (github.com/wasilibs/go-re2), has one, and reads a body two to four times
// faster with the same RE2 syntax. WAF_REGEX_ENGINE chooses: go (the
// default) or re2. go stays the default until re2 has run on real traffic
// with the same verdicts: it already differed on bytes that are not valid
// UTF-8 (AsRE2Input), which no corpus had shown. The rules, the pre-filter
// and the gates keep Go's regexp for their syntax; only the matching moves.
// A rule RE2 does not compile keeps Go's regexp and is logged.

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	re2 "github.com/wasilibs/go-re2"
)

// RegexEngines are the values WAF_REGEX_ENGINE takes.
var RegexEngines = []string{"re2", "go"}

var regexEngine = regexEngineFromEnv()

func regexEngineFromEnv() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WAF_REGEX_ENGINE")))
	if v == "" {
		return "go"
	}
	return v
}

// RegexEngine is the engine in force. ValidateRegexEngine says whether it is
// one the WAF knows; the WAF does not start on one it does not.
func RegexEngine() string { return regexEngine }

func ValidateRegexEngine() error {
	for _, e := range RegexEngines {
		if regexEngine == e {
			return nil
		}
	}
	return fmt.Errorf("WAF_REGEX_ENGINE=%q: want re2 or go", os.Getenv("WAF_REGEX_ENGINE"))
}

// compiledRE2 maps each rule's Go pattern to its RE2 form, built with the
// pre-filter and read without a lock.
var compiledRE2 atomic.Pointer[map[*regexp.Regexp]*re2.Regexp]

// buildRE2 compiles the RE2 form of every rule. A rule RE2 refuses keeps Go's
// regexp.
func buildRE2() {
	if regexEngine != "re2" {
		return
	}
	m := map[*regexp.Regexp]*re2.Regexp{}
	for _, cr := range blockRules {
		for _, rule := range cr.Rules {
			c, err := re2.Compile(rule.Pattern.String())
			if err != nil {
				slog.Warn("rule kept on Go's regexp: RE2 does not compile it", "rule", rule.ID, "error", err.Error())
				continue
			}
			m[rule.Pattern] = c
		}
	}
	compiledRE2.Store(&m)
}

// matchRule runs one rule's pattern with the engine in force: on goInput
// with Go's regexp, on re2Input (goInput as Go reads it, AsRE2Input) with RE2.
func matchRule(p *regexp.Regexp, goInput string, re2Input func() string) bool {
	if m := compiledRE2.Load(); m != nil {
		if c, ok := (*m)[p]; ok {
			return c.MatchString(re2Input())
		}
	}
	return p.MatchString(goInput)
}

// AsRE2Input is s as Go's regexp reads it, for RE2. Go reads each byte that
// is not part of a valid UTF-8 sequence as U+FFFD, which ., \S and [^...]
// match; RE2 matches nothing on such a byte, so a stray byte inside an attack
// would let it through ("<!ENTITY \xff SYSTEM"). Each such byte becomes
// U+FFFD, one for one, so counted repetitions read the same length.
func AsRE2Input(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString("\uFFFD")
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}
