package engine

// Gates for the rules the literal pre-filter cannot gate (prefilter.go).
//
// A rule whose pattern has no required literal of minGateLiteralLen bytes was
// scanned on every input: on a 64 KiB benign body that was 38 of the 43 rules
// evaluated and 31 of the 37 ms of regex time, Go's regexp having no DFA. Each
// gate here is a condition the rule's pattern cannot match without: a
// character it must contain, a run of digits or letters it must span, a short
// literal. A rule with no gate keeps being scanned on every input.
//
// Soundness is the whole point, as for the literal screen: a gate that is
// false while its rule could match is a silent bypass. The facts are read in
// the same terms the matcher scans: the input and its whitespace-compacted
// form (scanInput.hits). They are read from the compacted form, which has
// every character of the input but whitespace, runs at least as long, and the
// characters compaction makes whole: a multi-byte character split by a space
// is invalid in the input and valid once the space is gone. No gate needs a
// whitespace character. Literals are looked up in the pre-filter's
// screen (compacted, lowercased), with the long s folded to s: Go's (?i)
// matches U+017F for s and U+212A for k, and strings.ToLower maps only the
// Kelvin sign. TestGatesAreImpliedByTheirRules draws matching strings from
// each pattern's syntax tree, case folds included, and checks every gate.

import "strings"

// inputFacts is what the gates read, gathered in one pass over the
// compacted input.
type inputFacts struct {
	has      [128]bool // ASCII characters present, whitespace aside
	nonASCII bool
	// Longest runs.
	digitRun      int // [0-9]
	hexRun        int // [0-9a-fA-F]
	upperAlnumRun int // [A-Z0-9]
	alnumRun      int // [A-Za-z0-9], with the Kelvin sign and the long s, which (?i) folds to k and s
	b64Run        int // [A-Za-z0-9+/], with the same two
	// colonDigit: a colon followed by a digit.
	colonDigit bool
	// screen is the pre-filter's compacted, lowercased input, long s folded.
	screen string
}

func isGateSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\f' || r == '\r'
}

type runCounter struct{ cur, max int }

func (c *runCounter) step(in bool) {
	if in {
		c.cur++
		if c.cur > c.max {
			c.max = c.cur
		}
	} else {
		c.cur = 0
	}
}

// compactBytes is compactInput without a regex: the input without the bytes
// \s matches.
func compactBytes(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for i := 0; i < len(input); i++ {
		if c := input[i]; !isGateSpace(rune(c)) {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func gatherFacts(input, screen string) inputFacts {
	var f inputFacts
	var digit, hex, upper, alnum, b64 runCounter
	lastColon := false
	for _, r := range compactBytes(input) {
		folded := r == 0x212A || r == 0x17F
		if r >= 0x80 {
			f.nonASCII = true
		} else {
			f.has[r] = true
		}
		isDigit := r >= '0' && r <= '9'
		isUpper := r >= 'A' && r <= 'Z'
		isLower := r >= 'a' && r <= 'z'
		isHex := isDigit || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		isAlnum := isDigit || isUpper || isLower || folded
		digit.step(isDigit)
		hex.step(isHex)
		upper.step(isDigit || isUpper)
		alnum.step(isAlnum)
		b64.step(isAlnum || r == '+' || r == '/')
		if lastColon && isDigit {
			f.colonDigit = true
		}
		lastColon = r == ':'
	}
	f.digitRun, f.hexRun, f.upperAlnumRun, f.alnumRun, f.b64Run = digit.max, hex.max, upper.max, alnum.max, b64.max
	if strings.Contains(screen, "ſ") {
		screen = strings.ReplaceAll(screen, "ſ", "s")
	}
	f.screen = screen
	return f
}

func (f *inputFacts) any(chars string) bool {
	for i := 0; i < len(chars); i++ {
		if f.has[chars[i]] {
			return true
		}
	}
	return false
}

// lit reports whether one of the lowercase, whitespace-free literals is in
// the screen.
func (f *inputFacts) lit(lits ...string) bool {
	for _, l := range lits {
		if strings.Contains(f.screen, l) {
			return true
		}
	}
	return false
}

// ruleGates are the gates by rule ID, each the condition named in its
// comment. A gate here for a rule the literal screen already gates is never
// read; TestEveryGateIsForAnUngatedRule keeps the table to the rules it is
// for.
var ruleGates = map[string]func(f *inputFacts) bool{
	// \bOR\b\s+\d+\s*=\s*\d+ and the others: an = and a digit.
	"SQLi-006": func(f *inputFacts) bool { return f.has['='] && f.digitRun > 0 },
	// 0x + hex, or UNHEX( CHAR( CAST( CONVERT(.
	"SQLi-014": func(f *inputFacts) bool { return f.has['('] || f.lit("0x") },
	"SQLi-015": func(f *inputFacts) bool { return f.has['%'] },
	"SQLi-016": func(f *inputFacts) bool { return f.lit("/*") },
	// (OR|AND) ... = ...
	"SQLi-017": func(f *inputFacts) bool { return f.has['='] && f.lit("or", "and") },
	// a quote, then -- or #.
	"SQLi-018": func(f *inputFacts) bool { return f.any(`'"`) && (f.has['#'] || f.lit("--")) },
	// on<event>\s*=
	"XSS-003": func(f *inputFacts) bool { return f.has['='] && f.lit("on") },
	// {{...}}, ${...}, <%-...%>
	"XSS-009":  func(f *inputFacts) bool { return f.lit("{{", "${", "<%-") },
	"CMDi-001": func(f *inputFacts) bool { return f.has[';'] },
	"CMDi-002": func(f *inputFacts) bool { return f.has['|'] },
	"CMDi-003": func(f *inputFacts) bool { return f.lit("$(") },
	"CMDi-004": func(f *inputFacts) bool { return f.has['`'] },
	// a step up: two dots
	"DirT-001": func(f *inputFacts) bool { return f.lit("..") },
	"DirT-006": func(f *inputFacts) bool { return f.has['\\'] },
	"DirT-007": func(f *inputFacts) bool { return f.has['%'] },
	// <name>\s*=\s*<value>
	"DLP-001": func(f *inputFacts) bool {
		return f.has['='] && f.lit("password", "passwd", "pwd", "secret", "api_key", "apikey", "access_token", "auth_token")
	},
	// \d{3}-\d{2}-\d{4}
	"DLP-006":  func(f *inputFacts) bool { return f.has['-'] && f.digitRun >= 4 },
	"SSRF-007": func(f *inputFacts) bool { return f.colonDigit },
	"L4S-004":  func(f *inputFacts) bool { return f.lit("${") },
	// %name;
	"XXE-004": func(f *inputFacts) bool { return f.has['%'] && f.has[';'] },
	// Zero-width, bidi-override, Cyrillic and Greek characters.
	"UNI-001": func(f *inputFacts) bool { return f.nonASCII },
	"UNI-002": func(f *inputFacts) bool { return f.nonASCII },
	"UNI-003": func(f *inputFacts) bool { return f.nonASCII },
	"UNI-004": func(f *inputFacts) bool { return f.nonASCII },
	"UNI-005": func(f *inputFacts) bool { return f.nonASCII },
	// A prefix and 16 of [A-Z0-9]: 20 in a row.
	"CLOUD-001": func(f *inputFacts) bool { return f.upperAlnumRun >= 20 },
	// SK or AC, then 32 hex digits.
	"CLOUD-006": func(f *inputFacts) bool { return f.hexRun >= 32 },
	"CLOUD-007": func(f *inputFacts) bool { return f.hexRun >= 32 },
	"FILE-006":  func(f *inputFacts) bool { return f.lit(".pfx", ".p12", ".pem", ".key", ".ovpn") },
	// nc\s+-[lnvep]+\s
	"SHELL-007": func(f *inputFacts) bool { return f.has['-'] && f.lit("nc") },
	"SHELL-010": func(f *inputFacts) bool { return f.lit("iex", "invoke-expression", "invoke-webrequest", "iwr") },
	// 15 percent-escapes in a row.
	"PROTO-005": func(f *inputFacts) bool { return f.has['%'] },
	// 200 base64 characters in a row.
	"PROTO-006": func(f *inputFacts) bool { return f.b64Run >= 200 },
	// Card numbers: 13 to 16 digits in a row.
	"FIN-001": func(f *inputFacts) bool { return f.digitRun >= 13 },
	"FIN-002": func(f *inputFacts) bool { return f.digitRun >= 16 },
	"FIN-003": func(f *inputFacts) bool { return f.digitRun >= 15 },
	// IBAN: 15 to 34 of [A-Z0-9] in a row.
	"FIN-004": func(f *inputFacts) bool { return f.upperAlnumRun >= 15 },
	// 0x and 40 hex digits.
	"FIN-006": func(f *inputFacts) bool { return f.hexRun >= 40 },
	// Template delimiters (SERVER-SIDE TEMPLATE INJECTION).
	"SSTI-001": func(f *inputFacts) bool { return f.lit("{{") },
	"SSTI-002": func(f *inputFacts) bool { return f.lit("${") },
	"SSTI-003": func(f *inputFacts) bool { return f.lit("#{", "*{") },
	"SSTI-004": func(f *inputFacts) bool { return f.lit("@(") },
	"SSTI-005": func(f *inputFacts) bool { return f.lit("<%") },
	"SSTI-006": func(f *inputFacts) bool { return f.lit("{%") },
	// bitcoincash:..., or a base58 address of 26 to 35 characters.
	"RANSOM-003": func(f *inputFacts) bool { return f.alnumRun >= 26 || f.lit("bitcoincash:") },
}
