package main

import (
	"math"
	"strings"
	"unicode"
)

// DGA (Domain Generation Algorithm) detection using statistical analysis.
// Legitimate domains use common letter combinations (bigrams) from real words.
// Machine-generated domains have unusual bigram distributions and high entropy.

// Common English bigrams (top 30) — frequency from natural language corpus.
// DGA domains score LOW on these because they use random character combinations.
var commonBigrams = map[string]float64{
	"th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99,
	"re": 1.85, "on": 1.76, "at": 1.49, "en": 1.45, "nd": 1.35,
	"ti": 1.34, "es": 1.34, "or": 1.28, "te": 1.27, "of": 1.17,
	"ed": 1.17, "is": 1.13, "it": 1.12, "al": 1.09, "ar": 1.07,
	"st": 1.05, "to": 1.05, "nt": 1.04, "ng": 0.95, "se": 0.93,
	"ha": 0.93, "as": 0.87, "ou": 0.87, "io": 0.83, "le": 0.83,
	"co": 0.79, "me": 0.79, "de": 0.76, "hi": 0.76, "ri": 0.73,
	"ro": 0.73, "ic": 0.70, "ne": 0.69, "ea": 0.69, "ra": 0.69,
	"ce": 0.65, "li": 0.62, "ch": 0.60, "ll": 0.58, "be": 0.58,
	"ma": 0.57, "si": 0.55, "om": 0.55, "ur": 0.54, "ca": 0.53,
}

// DGAScore analyzes a domain name and returns a risk score 0-100.
// Higher = more likely DGA. Threshold ~70 for blocking.
type DGAResult struct {
	Score           int     `json:"score"`
	EntropyScore    float64 `json:"entropy_score"`
	BigramScore     float64 `json:"bigram_score"`
	LengthScore     float64 `json:"length_score"`
	ConsonantRatio  float64 `json:"consonant_ratio"`
	DigitRatio      float64 `json:"digit_ratio"`
	IsDGA           bool    `json:"is_dga"`
}

// AnalyzeDGA returns a DGA risk assessment for a domain.
func AnalyzeDGA(domain string) DGAResult {
	// Strip TLD — analyze only the registrable part
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return DGAResult{}
	}
	// Use second-level domain (e.g., "example" from "example.com")
	sld := parts[len(parts)-2]
	if len(sld) < 4 {
		return DGAResult{} // Too short to analyze meaningfully
	}

	var result DGAResult

	// 1. Shannon entropy of the SLD
	entropy := shannonEntropy(sld)
	// Normal domains: entropy 2.5-3.5, DGA: 3.8+
	result.EntropyScore = math.Min(100, math.Max(0, (entropy-2.5)*50))

	// 2. Bigram frequency score
	bigramHits := 0.0
	bigramTotal := 0.0
	for i := 0; i < len(sld)-1; i++ {
		bigram := sld[i : i+2]
		bigramTotal++
		if freq, ok := commonBigrams[bigram]; ok {
			bigramHits += freq
		}
	}
	if bigramTotal > 0 {
		avgBigramFreq := bigramHits / bigramTotal
		// Normal domains: avg 0.8+, DGA: 0.1-0.3
		result.BigramScore = math.Min(100, math.Max(0, (1.0-avgBigramFreq)*80))
	}

	// 3. Length score — DGA domains tend to be longer (12-30 chars)
	if len(sld) > 15 {
		result.LengthScore = math.Min(100, float64(len(sld)-15)*10)
	}

	// 4. Consonant ratio — DGA has unusual consonant clusters
	consonants := 0
	vowels := 0
	digits := 0
	for _, c := range sld {
		switch {
		case strings.ContainsRune("aeiou", c):
			vowels++
		case unicode.IsLetter(c):
			consonants++
		case unicode.IsDigit(c):
			digits++
		}
	}
	total := consonants + vowels
	if total > 0 {
		result.ConsonantRatio = float64(consonants) / float64(total)
		// Normal: 0.55-0.65, DGA: 0.7+ or 0.4-
		if result.ConsonantRatio > 0.75 || result.ConsonantRatio < 0.35 {
			result.ConsonantRatio = 80
		} else {
			result.ConsonantRatio = math.Abs(result.ConsonantRatio-0.6) * 200
		}
	}

	// 5. Digit ratio
	if len(sld) > 0 {
		result.DigitRatio = float64(digits) / float64(len(sld))
		if result.DigitRatio > 0.3 {
			result.DigitRatio = 90 // High digit ratio = very suspicious
		} else {
			result.DigitRatio = result.DigitRatio * 100
		}
	}

	// Weighted composite score
	result.Score = int(
		result.EntropyScore*0.30 +
			result.BigramScore*0.35 +
			result.LengthScore*0.10 +
			result.ConsonantRatio*0.15 +
			result.DigitRatio*0.10,
	)

	result.IsDGA = result.Score >= 70

	return result
}

// shannonEntropy is defined in entropy.go — shared across DGA and heuristics.
