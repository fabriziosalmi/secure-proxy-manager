package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-icap/icap"
)

const maxBodyInspectSize = 1 << 20 // 1 MB

// ── Rule engine types ───────────────────────────────────────────────────────

// Rule represents a single WAF detection pattern with metadata.
type Rule struct {
	ID       string         // Unique identifier, e.g. "SQLi-001"
	Pattern  *regexp.Regexp // Precompiled RE2 pattern
	Severity int            // Score contribution: 10=critical, 7=high, 4=medium, 2=low
	Tier     int            // Execution order: 1=fast, 2=moderate, 3=expensive
}

// CategoryRules groups rules by attack category.
type CategoryRules struct {
	Category string
	Rules    []Rule
}

// MatchResult captures what triggered a block.
type MatchResult struct {
	Category string
	RuleID   string
	Pattern  string
	Score    int
}

// ── Configuration ───────────────────────────────────────────────────────────

var (
	blockThreshold = 10 // Configurable via WAF_BLOCK_THRESHOLD env
	tarPitDelay    = 10 * time.Second
	ipBlockTracker = make(map[string][]time.Time)
	trackerMutex   sync.Mutex
)

func r(id string, pattern string, severity, tier int) Rule {
	return Rule{ID: id, Pattern: regexp.MustCompile(pattern), Severity: severity, Tier: tier}
}

// ── Rule definitions ────────────────────────────────────────────────────────

var blockRules = []CategoryRules{
	// ── SQL INJECTION ────────────────────────────────────────────────────
	{
		Category: "SQL_INJECTION",
		Rules: []Rule{
			// Tier 1 — fast keyword patterns
			r("SQLi-001", `(?i)(UNION\s+(ALL\s+)?SELECT)`, 10, 1),
			r("SQLi-002", `(?i)(DROP\s+(TABLE|DATABASE|INDEX|VIEW))`, 10, 1),
			r("SQLi-003", `(?i)(INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|TRUNCATE\s+TABLE)`, 7, 1),
			r("SQLi-004", `(?i)(;\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER|TRUNCATE|EXEC))`, 10, 1),

			// Tier 2 — compound patterns
			r("SQLi-005", `(?i)(WAITFOR\s+DELAY|BENCHMARK\s*\(|SLEEP\s*\(|pg_sleep\s*\()`, 10, 2),
			r("SQLi-006", `(?i)(\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+|\b1\s*=\s*1\b)`, 7, 2),
			r("SQLi-007", `(?i)(xp_cmdshell|sp_executesql|sp_configure|xp_regread)`, 10, 2),
			r("SQLi-008", `(?i)(LOAD_FILE\s*\(|INTO\s+(OUT|DUMP)FILE)`, 10, 2),
			r("SQLi-009", `(?i)(INFORMATION_SCHEMA|TABLE_SCHEMA|COLUMN_NAME|sys\.objects)`, 10, 2),

			// Tier 3 — evasion-hardened
			r("SQLi-010", `(?i)(0x[0-9a-f]{6,}|UNHEX\s*\(|CHAR\s*\(|CAST\s*\(|CONVERT\s*\()`, 4, 3),
			r("SQLi-011", `(?i)(%27|%23|%2d%2d)`, 4, 3),
			r("SQLi-012", `/\*.*\*/`, 2, 3),
		},
	},

	// ── XSS ATTACKS ─────────────────────────────────────────────────────
	{
		Category: "XSS_ATTACKS",
		Rules: []Rule{
			// Tier 1
			r("XSS-001", `(?i)<script[\s>]`, 10, 1),
			r("XSS-002", `(?i)(javascript\s*:|vbscript\s*:|data\s*:\s*text/html)`, 10, 1),

			// Tier 2
			r("XSS-003", `(?i)\bon(load|error|click|focus|blur|mouseover|mouseout|submit|reset|change|keydown|keyup|keypress|dblclick|contextmenu|drag(start|end|over)?|drop|paste|copy|cut|input)\s*=`, 10, 2),
			r("XSS-004", `(?i)(<iframe|<embed|<object|<applet|<form\s)`, 10, 2),
			r("XSS-005", `(?i)(<svg|<math|<animate|<set\s|<image\s)`, 10, 2),
			r("XSS-006", `(?i)(document\.(cookie|domain|write|location)|window\.(location|open)|eval\s*\(|Function\s*\()`, 10, 2),
			r("XSS-007", `(?i)(setTimeout|setInterval|execScript|msSetImmediate)\s*\(`, 4, 2),

			// Tier 3
			r("XSS-008", `(?i)(fromCharCode|String\.fromCharCode|atob\s*\(|btoa\s*\()`, 4, 3),
			r("XSS-009", `(\{\{.*\}\}|\$\{[^}]+\}|<%-.*%>)`, 4, 3),
			r("XSS-010", `(?i)(expression\s*\(|url\s*\(|@import)`, 4, 3),
		},
	},

	// ── COMMAND INJECTION ───────────────────────────────────────────────
	{
		Category: "COMMAND_INJECTION",
		Rules: []Rule{
			// Tier 1
			r("CMDi-001", `;\s*(ls|cat|id|whoami|uname|wget|curl|nc|ncat|bash|sh|dash|zsh|python|perl|ruby|php|node)\b`, 10, 1),
			r("CMDi-002", `\|\s*(cat|grep|sed|awk|cut|tr|base64|xxd|nc|bash|sh)\b`, 10, 1),

			// Tier 2
			r("CMDi-003", `\$\([^)]+\)`, 7, 2),
			r("CMDi-004", "`.+`", 7, 2),
			r("CMDi-005", `(?i)(;\s*rm\s+-rf|;\s*chmod\s+[0-7]{3,4}|;\s*chown\s+|;\s*mkfifo\s+)`, 10, 2),
			r("CMDi-006", `(?i)(cmd\s*/c|powershell\s+.*-[eE]|Start-Process|Invoke-Expression)`, 10, 2),

			// Tier 3
			r("CMDi-007", `(?i)(__import__\s*\(|subprocess\.|os\.(system|popen|exec)|exec\s*\()`, 7, 3),
			r("CMDi-008", `(?i)(\bsystem\s*\(|\bpassthru\s*\(|\bshell_exec\s*\(|\bproc_open\s*\()`, 7, 3),
		},
	},

	// ── DIRECTORY TRAVERSAL ─────────────────────────────────────────────
	{
		Category: "DIRECTORY_TRAVERSAL",
		Rules: []Rule{
			// Tier 1
			r("DirT-001", `(\.\./){2,}`, 10, 1),
			r("DirT-002", `(\.\.\\){2,}`, 10, 1),

			// Tier 2
			r("DirT-003", `(?i)/etc/(passwd|shadow|group|sudoers|hosts|crontab)`, 10, 2),
			r("DirT-004", `(?i)/(root|home/\w+)/\.(ssh|bash_history|bashrc|profile)`, 7, 2),
			r("DirT-005", `(?i)(windows[\\/]system32|windows[\\/]win\.ini|boot\.ini)`, 10, 2),
			r("DirT-006", `(?i)(\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._$-]+)`, 4, 2),

			// Tier 3
			r("DirT-007", `(?i)(%2e%2e|%252e%252e|%c0%ae|%c0%2f|%c1%1c|%c1%9c)`, 7, 3),
			r("DirT-008", `(%00|\\x00)`, 10, 3),
			r("DirT-009", `(?i)/proc/(self|version|cpuinfo|meminfo|net/)`, 10, 3),
		},
	},

	// ── DATA LEAK PREVENTION ────────────────────────────────────────────
	{
		Category: "DATA_LEAK_PREVENTION",
		Rules: []Rule{
			// Tier 2
			r("DLP-001", `(?i)(password|passwd|pwd|secret|api_key|apikey|access_token|auth_token)\s*=\s*[^\s&]{3,}`, 4, 2),
			r("DLP-002", `AKIA[0-9A-Z]{16}`, 10, 2),
			r("DLP-003", `ghp_[A-Za-z0-9_]{20,}`, 10, 2),
			r("DLP-004", `xox[bpras]-[0-9]{10,13}-`, 10, 2),
			r("DLP-005", `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY`, 10, 2),

			// Tier 3
			r("DLP-006", `\b\d{3}-\d{2}-\d{4}\b`, 2, 3),
			r("DLP-007", `(?i)(mongodb(\+srv)?://|postgres(ql)?://|mysql://|redis://)(\S+:)?\S+@`, 7, 3),
		},
	},

	// ── SSRF ────────────────────────────────────────────────────────────
	{
		Category: "SSRF",
		Rules: []Rule{
			// Tier 1
			r("SSRF-001", `(?i)(169\.254\.169\.254|metadata\.google\.internal)`, 10, 1),

			// Tier 2
			r("SSRF-002", `(?i)(http|https)://(127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+)`, 10, 2),
			r("SSRF-003", `(?i)(http|https)://(172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)`, 10, 2),
			r("SSRF-004", `(?i)/latest/(meta-data|user-data|dynamic|api/token)`, 10, 2),
			r("SSRF-005", `(?i)(file|gopher|dict|ftp)://`, 10, 2),

			// Tier 3
			r("SSRF-006", `(?i)(amazonaws\.com|compute\.googleapis\.com|management\.azure\.com)`, 4, 3),
			r("SSRF-007", `:(22|3306|5432|6379|11211|27017|9200|2375|2376)\b`, 4, 3),
		},
	},

	// ── LOG4SHELL / JNDI ────────────────────────────────────────────────
	{
		Category: "LOG4SHELL",
		Rules: []Rule{
			// Tier 1
			r("L4S-001", `(?i)\$\{[^}]*jndi\s*:`, 10, 1),

			// Tier 2
			r("L4S-002", `(?i)\$\{(lower|upper|env|sys|java|base64)[^}]*\}`, 7, 2),
			r("L4S-003", `(?i)(ldap|rmi|ldaps|dns|iiop|corba|nds)://`, 7, 2),

			// Tier 3
			r("L4S-004", `(?i)(\$\{.*){3,}`, 4, 3),
			r("L4S-005", `(?i)(ObjectInputStream|readObject|Runtime\.getRuntime|ProcessBuilder)`, 7, 3),
		},
	},

	// ── XXE ─────────────────────────────────────────────────────────────
	{
		Category: "XXE",
		Rules: []Rule{
			// Tier 1
			r("XXE-001", `(?i)<!ENTITY\s+\S+\s+SYSTEM`, 10, 1),
			r("XXE-002", `(?i)<!DOCTYPE\s+\S+\s+\[`, 7, 1),

			// Tier 2
			r("XXE-003", `(?i)(file|php|expect|data|java|jar|netdoc)://`, 7, 2),
			r("XXE-004", `(?i)%\w+;`, 4, 2),

			// Tier 3
			r("XXE-005", `(?i)(<!ENTITY\s+\S+\s+["'][^"']*["']\s*>.*){3,}`, 7, 3),
			r("XXE-006", `(?i)(CDATA\s*\[|PUBLIC\s+["'][^"']*["'])`, 4, 3),
		},
	},

	// ── PROTOTYPE POLLUTION ─────────────────────────────────────────────
	{
		Category: "PROTOTYPE_POLLUTION",
		Rules: []Rule{
			r("PP-001", `(__proto__|constructor\.prototype)`, 10, 2),
			r("PP-002", `\[["'](constructor|__proto__|prototype)["']\]\s*=`, 10, 2),
			r("PP-003", `(?i)(Object\.(assign|create|defineProperty|setPrototypeOf))`, 4, 3),
			r("PP-004", `(?i)(\["__proto__"\]|\['__proto__'\])`, 7, 3),
		},
	},

	// ── PATH MANIPULATION / FILE INCLUSION ───────────────────────────────
	{
		Category: "PATH_MANIPULATION",
		Rules: []Rule{
			r("PATH-001", `(?i)(php://filter|php://input|php://expect|php://fd)`, 10, 2),
			r("PATH-002", `(?i)(phar://|zip://|rar://|compress\.(zlib|bzip2)://)`, 10, 2),
			r("PATH-003", `(?i)(include|require|include_once|require_once)\s*\(`, 4, 3),
			r("PATH-004", `(?i)/var/(log|www)/.*\.(log|php|conf)`, 4, 3),
			r("PATH-005", `(?i)(convert\.iconv|convert\.base64)`, 4, 3),
		},
	},

	// ── UNICODE HOMOGRAPH OBFUSCATION ───────────────────────────────────
	{
		Category: "UNICODE_OBFUSCATION",
		Rules: []Rule{
			r("UNI-001", "(\xe2\x80\x8b|\xe2\x80\x8c|\xe2\x80\x8d)", 10, 1),
			r("UNI-002", "(\xe2\x80\xae|\xe2\x80\xad)", 10, 1),
			r("UNI-003", "(?i)[a-z]+[\xd0\xb0\xd0\xb5\xd0\xbe\xd1\x80\xd1\x81\xd1\x83\xd1\x96\xd1\x98]+[a-z]+", 7, 2),
			r("UNI-004", "(?i)[\xd0\xb0\xd0\xb5\xd0\xbe\xd1\x80\xd1\x81\xd1\x83\xd1\x96\xd1\x98]+[a-z]+", 4, 2),
			r("UNI-005", "(?i)[a-z]+[\xce\xbf\xce\xbd\xcf\x81\xcf\x84]+[a-z]+", 4, 2),
		},
	},
}

// textContentTypes lists Content-Type prefixes for which body inspection is meaningful.
var textContentTypes = []string{
	"application/x-www-form-urlencoded",
	"application/json",
	"application/xml",
	"text/xml",
	"text/",
	"multipart/form-data",
}

// ── Input normalization ─────────────────────────────────────────────────────

var (
	reDoubleEncode = regexp.MustCompile(`%25([0-9a-fA-F]{2})`)
	reNullBytes    = regexp.MustCompile("(%00|\\\\x00|&#0+;?|\x00)")
	reMultiSpace   = regexp.MustCompile(`\s{2,}`)
)

// normalizeInput applies anti-evasion transformations to the input.
func normalizeInput(input string) string {
	// Double-decode: %252e → %2e → .
	s := reDoubleEncode.ReplaceAllString(input, "%$1")

	// URL-decode
	if decoded, err := url.QueryUnescape(strings.ReplaceAll(s, "+", " ")); err == nil {
		s = decoded
	}

	// HTML entity decode
	s = html.UnescapeString(s)

	// Remove null bytes
	s = reNullBytes.ReplaceAllString(s, "")

	// Collapse whitespace
	s = reMultiSpace.ReplaceAllString(s, " ")

	return s
}

// ── Rule matching engine ────────────────────────────────────────────────────

// matchRulesScored evaluates input against all rules in tiered order.
// Returns all matches and the total anomaly score.
func matchRulesScored(input string) ([]MatchResult, int) {
	var matches []MatchResult
	totalScore := 0

	for tier := 1; tier <= 3; tier++ {
		// Early exit: if we already crossed the threshold, skip expensive tiers
		if totalScore >= blockThreshold && tier > 1 {
			break
		}

		for _, cr := range blockRules {
			for _, rule := range cr.Rules {
				if rule.Tier != tier {
					continue
				}
				if rule.Pattern.MatchString(input) {
					matches = append(matches, MatchResult{
						Category: cr.Category,
						RuleID:   rule.ID,
						Pattern:  rule.Pattern.String(),
						Score:    rule.Severity,
					})
					totalScore += rule.Severity
				}
			}
		}
	}

	return matches, totalScore
}

// ── Custom rules loader ─────────────────────────────────────────────────────

func loadCustomRules() {
	content, err := os.ReadFile("/config/waf_custom_rules.txt")
	if err != nil {
		log.Printf("Custom rules file not found or unreadable, using default rules only.\n")
		return
	}

	lines := strings.Split(string(content), "\n")
	var customRules []Rule

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			compiled, err := regexp.Compile("(?i)" + line)
			if err != nil {
				log.Printf("Error compiling custom rule %s: %v\n", line, err)
			} else {
				customRules = append(customRules, Rule{
					ID:       fmt.Sprintf("CUSTOM-%03d", i+1),
					Pattern:  compiled,
					Severity: 7,
					Tier:     2,
				})
			}
		}
	}

	if len(customRules) > 0 {
		blockRules = append(blockRules, CategoryRules{
			Category: "CUSTOM_USER_RULES",
			Rules:    customRules,
		})
		log.Printf("Loaded %d custom WAF rules.\n", len(customRules))
	}
}

func init() {
	if envThreshold := os.Getenv("WAF_BLOCK_THRESHOLD"); envThreshold != "" {
		if v, err := strconv.Atoi(envThreshold); err == nil && v > 0 {
			blockThreshold = v
		}
	}
	loadCustomRules()

	// Log rule counts
	total := 0
	for _, cr := range blockRules {
		total += len(cr.Rules)
	}
	log.Printf("WAF engine initialized: %d rules across %d categories (block threshold: %d)\n",
		total, len(blockRules), blockThreshold)
}

// ── Backend notification ────────────────────────────────────────────────────

func notifyBackend(data map[string]interface{}) {
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://backend:5000"
	}
	authUser := os.Getenv("BASIC_AUTH_USERNAME")
	authPass := os.Getenv("BASIC_AUTH_PASSWORD")
	if authUser == "" || authPass == "" {
		log.Printf("BASIC_AUTH_USERNAME/PASSWORD not set, skipping backend alert notification\n")
		return
	}

	payload, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal alert data: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", backendURL+"/api/internal/alert", bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("Failed to create alert request: %v\n", err)
		return
	}

	req.SetBasicAuth(authUser, authPass)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending alert to backend: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("Backend returned status %d\n", resp.StatusCode)
	}
}

// ── ICAP handlers ───────────────────────────────────────────────────────────

func handleOptions(w icap.ResponseWriter, req *icap.Request) {
	w.Header().Set("Methods", "REQMOD, RESPMOD")
	w.Header().Set("Service", "SecureProxy-WAF-2.0")
	w.Header().Set("Preview", "1024")
	w.Header().Set("Transfer-Preview", "*")
	w.Header().Set("Transfer-Ignore", "jpg,jpeg,gif,png,swf,flv,mp4,webm,woff2")
	w.Header().Set("Transfer-Complete", "")
	w.Header().Set("Max-Connections", "100")
	w.WriteHeader(200, nil, false)
}

func isTextContent(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, prefix := range textContentTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

func handleReqmod(w icap.ResponseWriter, req *icap.Request) {
	if req.Request == nil || req.Request.URL == nil {
		w.WriteHeader(204, nil, false)
		return
	}

	rawURL := req.Request.URL.String()
	normalizedURL := normalizeInput(rawURL)

	// Also check request headers for injection (Log4Shell, SSRF)
	var headerStr string
	for _, hdr := range []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "Accept", "Cookie"} {
		if v := req.Request.Header.Get(hdr); v != "" {
			headerStr += " " + v
		}
	}
	normalizedHeaders := normalizeInput(headerStr)

	// Combine URL + headers for scoring
	combined := normalizedURL + " " + normalizedHeaders
	matches, score := matchRulesScored(combined)

	// Check request body if score not yet over threshold
	var bodyStr string
	if score < blockThreshold && req.Request.Body != nil {
		ct := req.Request.Header.Get("Content-Type")
		if isTextContent(ct) {
			bodyBytes, readErr := io.ReadAll(io.LimitReader(req.Request.Body, maxBodyInspectSize))
			if readErr == nil && len(bodyBytes) > 0 {
				bodyStr = normalizeInput(string(bodyBytes))
				req.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				bodyMatches, bodyScore := matchRulesScored(bodyStr)
				matches = append(matches, bodyMatches...)
				score += bodyScore
			}
		}
	}

	// Log all matches for observability, even if below threshold
	if len(matches) > 0 && score < blockThreshold {
		ids := make([]string, len(matches))
		for i, m := range matches {
			ids[i] = m.RuleID
		}
		log.Printf("WAF OBSERVE score=%d/%d rules=[%s] url=%s\n",
			score, blockThreshold, strings.Join(ids, ","), truncate(rawURL, 200))
	}

	// Block if score meets threshold
	if score >= blockThreshold {
		source := "URL"
		if bodyStr != "" {
			source = "URL+BODY"
		}

		// Deduplicate categories for the alert
		cats := make(map[string]bool)
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			cats[m.Category] = true
			ids = append(ids, m.RuleID)
		}
		catList := make([]string, 0, len(cats))
		for c := range cats {
			catList = append(catList, c)
		}
		primaryCategory := catList[0]

		log.Printf("WAF BLOCKED score=%d/%d categories=[%s] rules=[%s] source=%s url=%s\n",
			score, blockThreshold, strings.Join(catList, ","), strings.Join(ids, ","),
			source, truncate(rawURL, 200))

		clientIP := "Unknown"
		if ipHeaders := req.Header.Values("X-Client-Ip"); len(ipHeaders) > 0 {
			clientIP = ipHeaders[0]
		}

		// Tar-pitting for repeat offenders
		if clientIP != "Unknown" {
			trackerMutex.Lock()
			now := time.Now()
			var validBlocks []time.Time
			for _, t := range ipBlockTracker[clientIP] {
				if now.Sub(t) < 60*time.Second {
					validBlocks = append(validBlocks, t)
				}
			}
			validBlocks = append(validBlocks, now)

			// Cleanup stale IPs
			for ip, times := range ipBlockTracker {
				var vb []time.Time
				for _, t := range times {
					if now.Sub(t) < 60*time.Second {
						vb = append(vb, t)
					}
				}
				if len(vb) == 0 {
					delete(ipBlockTracker, ip)
				} else {
					ipBlockTracker[ip] = vb
				}
			}

			ipBlockTracker[clientIP] = validBlocks
			blockCount := len(validBlocks)
			trackerMutex.Unlock()

			if blockCount > 3 {
				log.Printf("TAR-PITTING IP %s for %v (blocks=%d)\n", clientIP, tarPitDelay, blockCount)
				time.Sleep(tarPitDelay)
			}
		}

		alertData := map[string]interface{}{
			"event_type": "waf_block",
			"message":    fmt.Sprintf("WAF blocked %s — score %d, categories: %s", source, score, strings.Join(catList, ", ")),
			"details": map[string]interface{}{
				"category":   primaryCategory,
				"categories": catList,
				"rules":      ids,
				"score":      score,
				"threshold":  blockThreshold,
				"url":        truncate(rawURL, 500),
				"client_ip":  clientIP,
				"source":     source,
			},
			"level": "error",
		}
		go notifyBackend(alertData)

		sendBlockResponse(w, primaryCategory, score)
		return
	}

	w.WriteHeader(204, nil, false)
}

func handleRespmod(w icap.ResponseWriter, req *icap.Request) {
	if req.Response == nil {
		w.WriteHeader(204, nil, false)
		return
	}

	contentType := req.Response.Header.Get("Content-Type")
	contentTypeLower := strings.ToLower(contentType)

	dangerousTypes := []string{
		"application/x-msdownload", "application/x-dosexec",
		"application/x-executable", "application/x-sharedlib",
		"application/java-archive", "application/x-ms-shortcut",
	}
	for _, dt := range dangerousTypes {
		if strings.Contains(contentTypeLower, dt) {
			log.Printf("RESPMOD blocked dangerous content-type: %s\n", contentType)
			sendBlockResponse(w, "DANGEROUS_CONTENT_TYPE", 10)
			return
		}
	}

	w.WriteHeader(204, nil, false)
}

func sendBlockResponse(w icap.ResponseWriter, category string, score int) {
	body := fmt.Sprintf(
		`<html><body><h1>403 Forbidden</h1><p>Request blocked by WAF.</p><p>Category: <b>%s</b> | Score: %d</p></body></html>`,
		html.EscapeString(category), score)

	resp := &http.Response{
		Status:        "403 Forbidden",
		StatusCode:    403,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "text/html")
	w.WriteHeader(200, resp, true)
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// ── Main ────────────────────────────────────────────────────────────────────

func main() {
	icap.HandleFunc("/waf", func(w icap.ResponseWriter, req *icap.Request) {
		switch req.Method {
		case "OPTIONS":
			handleOptions(w, req)
		case "REQMOD":
			handleReqmod(w, req)
		case "RESPMOD":
			handleRespmod(w, req)
		default:
			w.WriteHeader(405, nil, false)
		}
	})

	// HTTP health + metrics endpoint
	go func() {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			total := 0
			for _, cr := range blockRules {
				total += len(cr.Rules)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"healthy","rules":%d,"categories":%d,"threshold":%d}`,
				total, len(blockRules), blockThreshold)
		})
		log.Printf("Starting health endpoint on :8080\n")
		if err := http.ListenAndServe(":8080", healthMux); err != nil {
			log.Printf("Health endpoint error: %v\n", err)
		}
	}()

	port := 1344
	log.Printf("Starting Go ICAP WAF server on port %d...\n", port)
	err := icap.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		log.Fatalf("Error starting server: %v\n", err)
	}
}
