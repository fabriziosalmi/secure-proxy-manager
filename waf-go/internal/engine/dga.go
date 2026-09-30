package engine

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

// DGAResult is the outcome of analysing a domain for DGA characteristics: a
// risk score 0-100 where higher means more likely generated, with the component
// scores behind it. Threshold ~70 for blocking.
type DGAResult struct {
	Score          int     `json:"score"`
	EntropyScore   float64 `json:"entropy_score"`
	BigramScore    float64 `json:"bigram_score"`
	LengthScore    float64 `json:"length_score"`
	ConsonantRatio float64 `json:"consonant_ratio"`
	DigitRatio     float64 `json:"digit_ratio"`
	IsDGA          bool    `json:"is_dga"`
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

	result := DGAResult{
		EntropyScore:   dgaEntropyScore(sld),
		BigramScore:    dgaBigramScore(sld),
		LengthScore:    dgaLengthScore(sld),
		ConsonantRatio: dgaConsonantScore(sld),
		DigitRatio:     dgaDigitScore(sld),
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

// dgaEntropyScore: Shannon entropy of the SLD.
// Normal domains: entropy 2.5-3.5, DGA: 3.8+
func dgaEntropyScore(sld string) float64 {
	return math.Min(100, math.Max(0, (ShannonEntropy(sld)-2.5)*50))
}

// dgaBigramScore: how far the SLD's letter pairs are from common ones.
// Normal domains: avg 0.8+, DGA: 0.1-0.3
func dgaBigramScore(sld string) float64 {
	bigramHits := 0.0
	bigramTotal := 0.0
	for i := 0; i < len(sld)-1; i++ {
		bigramTotal++
		if freq, ok := commonBigrams[sld[i:i+2]]; ok {
			bigramHits += freq
		}
	}
	if bigramTotal == 0 {
		return 0
	}
	return math.Min(100, math.Max(0, (1.0-bigramHits/bigramTotal)*80))
}

// dgaLengthScore: DGA domains tend to be longer (12-30 chars).
func dgaLengthScore(sld string) float64 {
	if len(sld) <= 15 {
		return 0
	}
	return math.Min(100, float64(len(sld)-15)*10)
}

// dgaConsonantScore: DGA has unusual consonant clusters.
// Normal: 0.55-0.65, DGA: 0.7+ or 0.4-
func dgaConsonantScore(sld string) float64 {
	consonants, vowels := 0, 0
	for _, c := range sld {
		switch {
		case strings.ContainsRune("aeiou", c):
			vowels++
		case unicode.IsLetter(c):
			consonants++
		}
	}
	total := consonants + vowels
	if total == 0 {
		return 0
	}
	ratio := float64(consonants) / float64(total)
	if ratio > 0.75 || ratio < 0.35 {
		return 80
	}
	return math.Abs(ratio-0.6) * 200
}

// dgaDigitScore: a high digit ratio is very suspicious.
func dgaDigitScore(sld string) float64 {
	digits := 0
	for _, c := range sld {
		if unicode.IsDigit(c) {
			digits++
		}
	}
	ratio := float64(digits) / float64(len(sld))
	if ratio > 0.3 {
		return 90
	}
	return ratio * 100
}

// shannonEntropy is defined in entropy.go — shared across DGA and heuristics.
