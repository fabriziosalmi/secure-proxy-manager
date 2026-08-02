package main

// Cheap pre-filter to skip the full rule set on benign input (issue #110).
//
// Before evaluating ~170 RE2 rules, screen the input against a set of literal
// keywords derived PROGRAMMATICALLY from each rule's compiled pattern. A rule is
// gated only by a literal that MUST appear for the regex to match (a "required
// literal"); rules with no extractable required literal are UNGATED and always
// run, so the pre-filter can never suppress a true positive.
//
// Soundness (no false negative) is the only thing that matters here — a wrong
// screen is a silent security bypass. The extractor is deliberately conservative:
// it returns a required-literal disjunction ONLY when it can prove necessity from
// the syntax tree, and returns "ungated" (always-scan) whenever unsure.
//
// The screen runs against the whitespace-COMPACTED, lowercased input. Because
// compact(L) is always a substring of compact(input) when L ⊆ input, screening
// the compacted form is a strict superset of both scans matchRulesScored does
// (raw `input` and `compact`), so evasion via inserted whitespace ("un ion
// select") can never slip past the gate.

import (
	"regexp/syntax"
	"strings"
	"sync"
)

// minGateLiteralLen is the shortest (compacted) literal we will gate a rule on.
// Shorter literals appear in too much benign traffic to be selective; a rule
// whose strongest required literal is shorter is left ungated (always scanned) —
// safe, just no speed-up for that rule.
const minGateLiteralLen = 3

// prefilter holds the compiled screen. nil-safe: if it is nil (build failed),
// matchRulesScored falls back to scanning every rule.
type prefilter struct {
	ac       *acMatcher          // over the compacted, lowercased required literals
	lit2rule map[string][]string // required literal → rule IDs that require it
	ungated  map[string]struct{} // rule IDs with no extractable required literal
}

var (
	activePrefilter *prefilter
	prefilterMu     sync.RWMutex
)

// buildPrefilter (re)computes the screen from the current blockRules. Call after
// loadCustomRules() and whenever the effective rule set changes. On any doubt a
// rule is placed in `ungated`, so the result is always sound.
func buildPrefilter() {
	pf := &prefilter{
		lit2rule: make(map[string][]string),
		ungated:  make(map[string]struct{}),
	}
	litSet := make(map[string]struct{})

	for _, cr := range blockRules {
		for _, rule := range cr.Rules {
			lits := ruleGateKeys(rule.Pattern.String())
			if len(lits) == 0 {
				pf.ungated[rule.ID] = struct{}{}
				continue
			}
			for _, l := range lits {
				pf.lit2rule[l] = append(pf.lit2rule[l], rule.ID)
				litSet[l] = struct{}{}
			}
		}
	}

	keywords := make([]string, 0, len(litSet))
	for l := range litSet {
		keywords = append(keywords, l)
	}
	pf.ac = newACMatcher(keywords)

	prefilterMu.Lock()
	activePrefilter = pf
	prefilterMu.Unlock()
}

// prefilterActive returns the set of rule IDs that COULD match `input` (every
// ungated rule, plus every gated rule whose required literal is present), and
// ok=true. If ok is false the caller must scan all rules (no screen built).
// When the returned set is empty, no rule can possibly match.
func prefilterActive(input string) (active map[string]struct{}, ok bool) {
	prefilterMu.RLock()
	pf := activePrefilter
	prefilterMu.RUnlock()
	if pf == nil || pf.ac == nil {
		return nil, false
	}

	// Screen the compacted, lowercased input — a superset of both the raw and
	// compact scans (see file header).
	screen := compactInput(strings.ToLower(input))

	active = make(map[string]struct{}, len(pf.ungated)+8)
	for id := range pf.ungated {
		active[id] = struct{}{}
	}
	for lit := range pf.ac.presentKeywords(screen) {
		for _, id := range pf.lit2rule[lit] {
			active[id] = struct{}{}
		}
	}
	return active, true
}

// ── Required-literal extraction (soundness-critical) ─────────────────────────

// ruleGateKeys parses a rule's source pattern and returns a required-literal
// disjunction: a set of literals such that the pattern can match ONLY IF the
// (compacted, lowercased) input contains at least one of them. Returns nil when
// no such set can be proven (→ the rule is ungated / always scanned).
func ruleGateKeys(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil // unpariseable → ungated (safe)
	}
	re = re.Simplify()
	lits := requiredLiteralDisjunction(re)
	if len(lits) == 0 {
		return nil
	}
	// Normalize to the screen's alphabet and enforce the minimum length. If ANY
	// alternative is too short after normalization, the disjunction is too weak
	// to gate soundly-and-usefully → ungate the whole rule.
	out := make([]string, 0, len(lits))
	seen := make(map[string]struct{}, len(lits))
	for _, l := range lits {
		k := compactInput(strings.ToLower(l))
		if len(k) < minGateLiteralLen {
			return nil
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// requiredLiteralDisjunction walks the syntax tree and returns a set D of
// literals such that any match of re contains at least one element of D, or nil
// if no such set is provable. INVARIANT (soundness): a non-nil result is a true
// necessary disjunction — the regex cannot match a string lacking every element.
func requiredLiteralDisjunction(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		s := string(re.Rune)
		if s == "" {
			return nil
		}
		return []string{s}

	case syntax.OpCapture:
		return requiredLiteralDisjunction(re.Sub[0])

	case syntax.OpPlus: // one-or-more → the sub must match at least once
		return requiredLiteralDisjunction(re.Sub[0])

	case syntax.OpRepeat: // {min,max}; only mandatory when min >= 1
		if re.Min >= 1 {
			return requiredLiteralDisjunction(re.Sub[0])
		}
		return nil

	case syntax.OpConcat:
		// Every child must match, so ANY single child's required disjunction is
		// also required for the whole. Pick the most selective one (largest
		// minimum-length literal).
		var best []string
		bestMin := 0
		for _, sub := range re.Sub {
			d := requiredLiteralDisjunction(sub)
			if len(d) == 0 {
				continue
			}
			if m := minLen(d); m > bestMin {
				best, bestMin = d, m
			}
		}
		return best

	case syntax.OpAlternate:
		// Matches if ANY branch matches. A literal is required for the whole only
		// if EVERY branch requires one; then the union is the necessary set. If a
		// single branch has no required literal, the whole is ungated.
		var union []string
		for _, sub := range re.Sub {
			d := requiredLiteralDisjunction(sub)
			if len(d) == 0 {
				return nil
			}
			union = append(union, d...)
		}
		return union

	default:
		// OpStar, OpQuest (match empty), OpCharClass, OpAnyChar*, anchors,
		// OpEmptyMatch, OpWordBoundary, … contribute no required literal.
		return nil
	}
}

func minLen(ss []string) int {
	m := 0
	for i, s := range ss {
		if i == 0 || len(s) < m {
			m = len(s)
		}
	}
	return m
}

// ── Aho-Corasick (multi-substring presence) ─────────────────────────────────
// Minimal, allocation-light matcher: build once, then presentKeywords does a
// single linear pass and reports which keywords occur in the text.

type acNode struct {
	next   map[byte]int
	fail   int
	output []int // keyword indices ending at this node
}

type acMatcher struct {
	nodes    []acNode
	keywords []string
}

func newACMatcher(keywords []string) *acMatcher {
	m := &acMatcher{keywords: keywords}
	m.nodes = []acNode{{next: make(map[byte]int)}} // root = 0

	// Trie.
	for idx, kw := range keywords {
		if kw == "" {
			continue
		}
		cur := 0
		for i := 0; i < len(kw); i++ {
			b := kw[i]
			nxt, ok := m.nodes[cur].next[b]
			if !ok {
				nxt = len(m.nodes)
				m.nodes = append(m.nodes, acNode{next: make(map[byte]int)})
				m.nodes[cur].next[b] = nxt
			}
			cur = nxt
		}
		m.nodes[cur].output = append(m.nodes[cur].output, idx)
	}

	// Failure links (BFS).
	queue := make([]int, 0, len(m.nodes))
	for _, s := range m.nodes[0].next {
		m.nodes[s].fail = 0
		queue = append(queue, s)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for b, nxt := range m.nodes[cur].next {
			// Compute fail(nxt).
			f := m.nodes[cur].fail
			for f != 0 {
				if _, ok := m.nodes[f].next[b]; ok {
					break
				}
				f = m.nodes[f].fail
			}
			if fn, ok := m.nodes[f].next[b]; ok && fn != nxt {
				f = fn
			} else {
				f = 0
			}
			m.nodes[nxt].fail = f
			// Merge outputs along the fail link so a single node reports all
			// suffixes that are keywords.
			m.nodes[nxt].output = append(m.nodes[nxt].output, m.nodes[f].output...)
			queue = append(queue, nxt)
		}
	}
	return m
}

// presentKeywords returns the set of keyword strings that occur in text.
func (m *acMatcher) presentKeywords(text string) map[string]struct{} {
	found := make(map[string]struct{})
	if m == nil || len(m.nodes) == 0 {
		return found
	}
	cur := 0
	for i := 0; i < len(text); i++ {
		b := text[i]
		for cur != 0 {
			if _, ok := m.nodes[cur].next[b]; ok {
				break
			}
			cur = m.nodes[cur].fail
		}
		if nxt, ok := m.nodes[cur].next[b]; ok {
			cur = nxt
		} else {
			cur = 0
		}
		for _, idx := range m.nodes[cur].output {
			found[m.keywords[idx]] = struct{}{}
		}
	}
	return found
}
