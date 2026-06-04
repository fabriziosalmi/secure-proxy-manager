package main

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Typosquatting detection using Levenshtein distance against a list
// of known legitimate domains. If a requested domain is 1-2 edits away
// from a known domain but NOT the domain itself, it's likely typosquatting.

// Top domains that attackers commonly typosquat.
var protectedDomains = []string{
	// Tech
	"google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
	"github.com", "gitlab.com", "stackoverflow.com", "cloudflare.com",
	"twitter.com", "linkedin.com", "youtube.com", "instagram.com",
	// Finance
	"paypal.com", "stripe.com", "chase.com", "bankofamerica.com",
	// Cloud
	"aws.amazon.com", "azure.microsoft.com", "cloud.google.com",
	"console.aws.amazon.com", "portal.azure.com",
	// Security
	"virustotal.com", "abuseipdb.com",
	// Email
	"gmail.com", "outlook.com", "yahoo.com", "protonmail.com",
}

// TyposquatResult describes a typosquatting detection.
type TyposquatResult struct {
	Suspicious bool   `json:"suspicious"`
	Target     string `json:"target"`    // The legitimate domain being impersonated
	Distance   int    `json:"distance"`  // Edit distance
	Technique  string `json:"technique"` // e.g., "homoglyph", "transposition", "omission"
}

// protectedSLD maps each brand's second-level label to its registrable domain,
// derived public-suffix-aware so multi-label entries collapse to the brand
// (aws.amazon.com -> amazon) and public suffixes are excluded.
var protectedSLD = buildProtectedSLD()

func buildProtectedSLD() map[string]string {
	m := make(map[string]string)
	for _, pd := range protectedDomains {
		if sld, reg, ok := splitRegistrable(pd); ok {
			m[sld] = reg
		}
	}
	return m
}

// splitRegistrable returns the second-level label and the registrable domain
// (eTLD+1) for a host, public-suffix aware. ok is false when the host is a
// public suffix itself (e.g. github.io), invalid, or has no registrable part.
func splitRegistrable(domain string) (sld, registrable string, ok bool) {
	domain = strings.TrimPrefix(strings.ToLower(domain), "www.")
	reg, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", "", false
	}
	i := strings.IndexByte(reg, '.')
	if i <= 0 {
		return "", "", false
	}
	return reg[:i], reg, true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// isAdjacentTransposition reports whether a and b are equal length and differ
// by exactly one swap of two adjacent characters (e.g. "goolge" <-> "google").
func isAdjacentTransposition(a, b string) bool {
	if len(a) != len(b) || a == b {
		return false
	}
	i := 0
	for i < len(a) && a[i] == b[i] {
		i++
	}
	if i+1 >= len(a) || a[i] != b[i+1] || a[i+1] != b[i] {
		return false
	}
	return a[:i]+string(a[i+1])+string(a[i])+a[i+2:] == b
}

// CheckTyposquat reports whether a domain is a likely typosquat of a protected
// brand. It compares the registrable second-level label (public-suffix aware),
// so legitimate same-brand domains on other TLDs/suffixes (github.io, yahoo.co)
// and unrelated names (chess.com vs chase.com) are not flagged — only a single
// edit of a brand label, or a homoglyph that resolves to one, is suspicious.
func CheckTyposquat(domain string) TyposquatResult {
	sld, _, ok := splitRegistrable(domain)
	if !ok || len(sld) < 3 {
		return TyposquatResult{}
	}
	if _, isBrand := protectedSLD[sld]; isBrand {
		return TyposquatResult{} // exact brand label on any TLD — legitimate
	}
	// A single edit (g1thub, paypa1, goggle) or an adjacent-character swap
	// (goolge, googel) of a brand label. Adjacent transposition is included
	// explicitly because it is a real typo technique, while NOT matching
	// unrelated 2-edit names (chess.com vs chase.com is not a swap).
	for brand, reg := range protectedSLD {
		if abs(len(sld)-len(brand)) > 1 {
			continue
		}
		if levenshtein(sld, brand) == 1 {
			return TyposquatResult{Suspicious: true, Target: reg, Distance: 1, Technique: classifyTechnique(sld, brand)}
		}
		if isAdjacentTransposition(sld, brand) {
			return TyposquatResult{Suspicious: true, Target: reg, Distance: 2, Technique: "transposition"}
		}
	}
	// Homoglyph substitution that resolves to a brand label (visual confusion).
	if de := replaceHomoglyphs(sld); de != sld {
		if reg, isBrand := protectedSLD[de]; isBrand {
			return TyposquatResult{Suspicious: true, Target: reg, Distance: levenshtein(sld, de), Technique: "homoglyph"}
		}
	}
	return TyposquatResult{}
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Use two rows instead of full matrix (O(min(m,n)) space)
	if la < lb {
		a, b = b, a
		la, lb = lb, la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// classifyTechnique guesses what kind of typosquatting technique was used.
func classifyTechnique(typo, legit string) string {
	if len(typo) < len(legit) {
		return "omission" // Character removed: goole.com
	}
	if len(typo) > len(legit) {
		return "addition" // Character added: googgle.com
	}
	// Same length — check for transposition or substitution
	diffs := 0
	for i := 0; i < len(typo) && i < len(legit); i++ {
		if typo[i] != legit[i] {
			diffs++
		}
	}
	if diffs == 2 {
		return "transposition" // Characters swapped: googel.com
	}
	return "substitution" // Character replaced: g00gle.com
}

// replaceHomoglyphs replaces common lookalike characters with their ASCII equivalents.
var homoglyphs = map[rune]rune{
	'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
	'6': 'g', '7': 't', '8': 'b', '9': 'q',
	// Common Unicode confusables
	0x0430: 'a', // Cyrillic а
	0x0435: 'e', // Cyrillic е
	0x043E: 'o', // Cyrillic о
	0x0440: 'p', // Cyrillic р
	0x0441: 'c', // Cyrillic с
	0x0443: 'y', // Cyrillic у
	0x0445: 'x', // Cyrillic х
}

func replaceHomoglyphs(s string) string {
	// First handle multi-character homoglyphs
	s = strings.ReplaceAll(s, "rn", "m")
	s = strings.ReplaceAll(s, "vv", "w")

	var b strings.Builder
	for _, c := range s {
		if replacement, ok := homoglyphs[c]; ok {
			b.WriteRune(replacement)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}
