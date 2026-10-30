// Package regexsample draws strings from a regular expression's syntax tree,
// for tests that check a gate or a second regex engine against the rules.
package regexsample

import (
	"math/rand"
	"regexp/syntax"
	"strings"
	"unicode"
)

// Draw writes a string from a pattern's syntax tree. It covers what the
// rule set uses; assertions (^, $, \b) produce nothing, so a draw may not
// match, and the caller keeps only the draws that do. A case-folded literal
// takes any member of each rune's fold orbit, so (?i)s yields s, S and the
// long s, and (?i)k the Kelvin sign.
func Draw(re *syntax.Regexp, r *rand.Rand, b *strings.Builder) {
	switch re.Op {
	case syntax.OpLiteral:
		for _, c := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				orbit := []rune{c}
				for f := unicode.SimpleFold(c); f != c; f = unicode.SimpleFold(f) {
					orbit = append(orbit, f)
				}
				c = orbit[r.Intn(len(orbit))]
			}
			b.WriteRune(c)
		}
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			return
		}
		// Go's regexp reads a byte that is not valid UTF-8 as U+FFFD: where a
		// class takes U+FFFD, a stray byte is sometimes drawn instead.
		if classHas(re.Rune, 0xFFFD) && r.Intn(4) == 0 {
			b.WriteString(strayBytes[r.Intn(len(strayBytes))])
			return
		}
		i := r.Intn(len(re.Rune)/2) * 2
		lo, hi := re.Rune[i], re.Rune[i+1]
		if hi-lo > 0xFFFF {
			hi = lo + 0xFFFF
		}
		b.WriteRune(lo + rune(r.Intn(int(hi-lo)+1)))
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		if r.Intn(4) == 0 {
			b.WriteString(strayBytes[r.Intn(len(strayBytes))])
			return
		}
		const pool = "abcXYZ019 _-./:;=%'\"()<>{}$#éſKа"
		rs := []rune(pool)
		b.WriteRune(rs[r.Intn(len(rs))])
	case syntax.OpCapture:
		Draw(re.Sub[0], r, b)
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		lo, hi := 0, 3
		switch re.Op {
		case syntax.OpPlus:
			lo = 1
		case syntax.OpQuest:
			hi = 1
		case syntax.OpRepeat:
			lo, hi = re.Min, re.Max
			if hi < 0 || hi > lo+3 {
				hi = lo + 3
			}
		}
		for n := lo + r.Intn(hi-lo+1); n > 0; n-- {
			Draw(re.Sub[0], r, b)
		}
	case syntax.OpConcat:
		for _, s := range re.Sub {
			Draw(s, r, b)
		}
	case syntax.OpAlternate:
		Draw(re.Sub[r.Intn(len(re.Sub))], r, b)
	}
}

// strayBytes are not valid UTF-8: a lone continuation byte, half a character,
// a lead byte with nothing after it.
var strayBytes = []string{"\xff", "\xe2\x84", "\xc5", "\x80"}

func classHas(ranges []rune, c rune) bool {
	for i := 0; i+1 < len(ranges); i += 2 {
		if ranges[i] <= c && c <= ranges[i+1] {
			return true
		}
	}
	return false
}
