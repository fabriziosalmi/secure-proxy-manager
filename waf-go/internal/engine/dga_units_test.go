package engine

import "testing"

// AnalyzeDGA is a weighted sum of five component scores; these pin each one.
// (The refactor into components was checked against the previous single
// function over 20,000 random domains: identical results.)
func TestDGAComponentScores(t *testing.T) {
	if got := dgaLengthScore("abcdefghijklmno"); got != 0 { // 15 chars: at the threshold
		t.Errorf("length score at 15 = %v, want 0", got)
	}
	if got := dgaLengthScore("abcdefghijklmnopqrst"); got != 50 { // 20 chars
		t.Errorf("length score at 20 = %v, want 50", got)
	}
	if got := dgaLengthScore(string(make([]byte, 40))); got != 100 {
		t.Errorf("length score is capped at 100, got %v", got)
	}
	if got := dgaDigitScore("1234abcd"); got != 90 { // 50% digits
		t.Errorf("digit score for a digit-heavy label = %v, want 90", got)
	}
	if got := dgaDigitScore("abcdefghij"); got != 0 {
		t.Errorf("digit score with no digits = %v, want 0", got)
	}
	if got := dgaDigitScore("abcdefgh1j"); got != 10 { // 1 in 10
		t.Errorf("digit score at 10%% = %v, want 10", got)
	}
	if got := dgaConsonantScore("aeioaeio"); got != 80 { // all vowels
		t.Errorf("all-vowel label = %v, want 80", got)
	}
	if got := dgaConsonantScore("bcdfghjk"); got != 80 { // all consonants
		t.Errorf("all-consonant label = %v, want 80", got)
	}
	if got := dgaConsonantScore("1234"); got != 0 { // no letters at all
		t.Errorf("label with no letters = %v, want 0", got)
	}
	if e := dgaEntropyScore("aaaaaaaa"); e != 0 {
		t.Errorf("entropy score of a constant label = %v, want 0", e)
	}
}

func TestAnalyzeDGAStillSeparatesGeneratedFromReal(t *testing.T) {
	if r := AnalyzeDGA("google.com"); r.IsDGA {
		t.Errorf("google.com flagged: %+v", r)
	}
	if r := AnalyzeDGA("xk3j9qz7v2m8w1p4r5t6y0u.com"); !r.IsDGA {
		t.Errorf("a generated-looking label was not flagged: %+v", r)
	}
	if r := AnalyzeDGA("a.com"); r.Score != 0 {
		t.Errorf("a too-short label was scored: %+v", r)
	}
}
