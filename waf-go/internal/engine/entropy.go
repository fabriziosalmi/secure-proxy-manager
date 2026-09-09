package engine

import "math"

// ShannonEntropy returns the Shannon entropy of s in bits per byte, rounded to
// two decimals.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return math.Round(entropy*100) / 100
}
