package main

import (
	"strings"
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
	Suspicious    bool   `json:"suspicious"`
	Target        string `json:"target"`         // The legitimate domain being impersonated
	Distance      int    `json:"distance"`        // Edit distance
	Technique     string `json:"technique"`       // e.g., "homoglyph", "transposition", "omission"
}

// CheckTyposquat checks if a domain looks like a typosquat of a known domain.
func CheckTyposquat(domain string) TyposquatResult {
	domain = strings.ToLower(domain)

	// Strip www. prefix
	domain = strings.TrimPrefix(domain, "www.")

	// Extract registrable domain (last 2 parts)
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return TyposquatResult{}
	}
	checkDomain := strings.Join(parts[len(parts)-2:], ".")

	// Skip if it's an exact match (it's the real domain)
	for _, pd := range protectedDomains {
		if checkDomain == pd {
			return TyposquatResult{}
		}
	}

	// Check Levenshtein distance against each protected domain
	for _, pd := range protectedDomains {
		dist := levenshtein(checkDomain, pd)
		if dist >= 1 && dist <= 2 {
			technique := classifyTechnique(checkDomain, pd)
			return TyposquatResult{
				Suspicious: true,
				Target:     pd,
				Distance:   dist,
				Technique:  technique,
			}
		}
	}

	// Also check common homoglyph substitutions
	deHomoglyphed := replaceHomoglyphs(checkDomain)
	if deHomoglyphed != checkDomain {
		for _, pd := range protectedDomains {
			if deHomoglyphed == pd {
				return TyposquatResult{
					Suspicious: true,
					Target:     pd,
					Distance:   0,
					Technique:  "homoglyph",
				}
			}
		}
	}

	return TyposquatResult{}
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 { return lb }
	if lb == 0 { return la }

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
		if a < c { return a }
		return c
	}
	if b < c { return b }
	return c
}

// classifyTechnique guesses what kind of typosquatting technique was used.
func classifyTechnique(typo, legit string) string {
	if len(typo) < len(legit) {
		return "omission"   // Character removed: goole.com
	}
	if len(typo) > len(legit) {
		return "addition"   // Character added: googgle.com
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
	return "substitution"     // Character replaced: g00gle.com
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
