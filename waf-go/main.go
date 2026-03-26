package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-icap/icap"
)

const maxBodyInspectSize = 1 << 20 // 1 MB

var (
	tarPitDelay    = 10 * time.Second
	ipBlockTracker = make(map[string][]time.Time)
	trackerMutex   sync.Mutex
)

type CategoryRules struct {
	Category string
	Rules    []*regexp.Regexp
}

var blockRules = []CategoryRules{
	{
		Category: "SQL_INJECTION",
		Rules: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM)`),
			regexp.MustCompile(`(?i)(%27|'|--|%23|#)(.*)(OR|AND)\s+([0-9=a-zA-Z]+)`),
		},
	},
	{
		Category: "XSS_ATTACKS",
		Rules: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(<script>|javascript:|onerror=|onload=|eval\()`),
			regexp.MustCompile(`(?i)(document\.cookie|window\.location)`),
		},
	},
	{
		Category: "DATA_LEAK_PREVENTION",
		Rules: []*regexp.Regexp{
			regexp.MustCompile(`CONFIDENTIAL_SECRET_[0-9]+`),
			regexp.MustCompile(`(?i)(password|passwd|pwd)=([^&]+)`),
		},
	},
	{
		Category: "DIRECTORY_TRAVERSAL",
		Rules: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow)`),
		},
	},
	{
		Category: "COMMAND_INJECTION",
		Rules: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(;\s*ls\s+-|;\s*cat\s+|;\s*wget\s+|;\s*curl\s+|;\s*rm\s+-rf)`),
		},
	},
	{
		Category: "UNICODE_HOMOGRAPH_OBFUSCATION",
		Rules: []*regexp.Regexp{
			regexp.MustCompile(`(\xe2\x80\x8b|\xe2\x80\x8c|\xe2\x80\x8d)`),
			regexp.MustCompile(`(\xe2\x80\xae|\xe2\x80\xad)`),
			regexp.MustCompile(`(?i)[a-z]+[\xd0\xb0\xd0\xb5\xd0\xbe\xd1\x80\xd1\x81\xd1\x83\xd1\x96\xd1\x98]+[a-z]+`),
			regexp.MustCompile(`(?i)[\xd0\xb0\xd0\xb5\xd0\xbe\xd1\x80\xd1\x81\xd1\x83\xd1\x96\xd1\x98]+[a-z]+`),
			regexp.MustCompile(`(?i)[a-z]+[\xce\xbf\xce\xbd\xcf\x81\xcf\x84]+[a-z]+`),
		},
	},
}

// textContentTypes lists Content-Type prefixes for which body inspection is meaningful.
var textContentTypes = []string{
	"application/x-www-form-urlencoded",
	"application/json",
	"application/xml",
	"text/",
	"multipart/form-data",
}

func loadCustomRules() {
	content, err := os.ReadFile("/config/waf_custom_rules.txt")
	if err != nil {
		log.Printf("Custom rules file not found or unreadable, using default rules only.\n")
		return
	}

	lines := strings.Split(string(content), "\n")
	var customRegexes []*regexp.Regexp

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			r, err := regexp.Compile("(?i)" + line)
			if err != nil {
				log.Printf("Error compiling custom rule %s: %v\n", line, err)
			} else {
				customRegexes = append(customRegexes, r)
			}
		}
	}

	if len(customRegexes) > 0 {
		blockRules = append(blockRules, CategoryRules{
			Category: "CUSTOM_USER_RULES",
			Rules:    customRegexes,
		})
		log.Printf("Loaded %d custom WAF rules.\n", len(customRegexes))
	}
}

func init() {
	loadCustomRules()
}

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

func handleOptions(w icap.ResponseWriter, req *icap.Request) {
	log.Println("Received OPTIONS request")
	w.Header().Set("Methods", "REQMOD, RESPMOD")
	w.Header().Set("Service", "SecureProxy-WAF-1.0")
	w.Header().Set("Preview", "1024")
	w.Header().Set("Transfer-Preview", "*")
	w.Header().Set("Transfer-Ignore", "jpg,jpeg,gif,png,swf,flv")
	w.Header().Set("Transfer-Complete", "")
	w.Header().Set("Max-Connections", "100")
	w.WriteHeader(200, nil, false)
}

// isTextContent returns true if the Content-Type indicates a text-based body worth inspecting.
func isTextContent(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, prefix := range textContentTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

// matchRules checks input against all block rules and returns the matching category (or "").
func matchRules(input string) (string, string) {
	for _, cr := range blockRules {
		for _, rule := range cr.Rules {
			if rule.MatchString(input) {
				return cr.Category, rule.String()
			}
		}
	}
	return "", ""
}

func handleReqmod(w icap.ResponseWriter, req *icap.Request) {
	if req.Request == nil || req.Request.URL == nil {
		w.WriteHeader(204, nil, false)
		return
	}

	rawURL := req.Request.URL.String()

	// Decode URL
	decodedURL, err := url.QueryUnescape(strings.ReplaceAll(rawURL, "+", " "))
	if err != nil {
		decodedURL = rawURL
	}

	log.Printf("INSPECTING URL: %s\n", decodedURL)

	// Check URL against rules
	category, ruleStr := matchRules(decodedURL)

	// Check request body against rules (POST/PUT payloads)
	var bodyStr string
	if category == "" && req.Request.Body != nil {
		ct := req.Request.Header.Get("Content-Type")
		if isTextContent(ct) {
			bodyBytes, readErr := io.ReadAll(io.LimitReader(req.Request.Body, maxBodyInspectSize))
			if readErr == nil && len(bodyBytes) > 0 {
				bodyStr = string(bodyBytes)
				// Restore body so Squid can forward it
				req.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				category, ruleStr = matchRules(bodyStr)
				if category != "" {
					log.Printf("INSPECTING BODY (%d bytes): matched\n", len(bodyBytes))
				}
			}
		}
	}

	if category != "" {
		source := "URL"
		if bodyStr != "" {
			source = "BODY"
		}
		log.Printf("WAF BLOCKED [%s] in %s - Matched rule %s\n", category, source, ruleStr)

		clientIP := "Unknown"
		if ipHeaders := req.Header.Values("X-Client-Ip"); len(ipHeaders) > 0 {
			clientIP = ipHeaders[0]
		}

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

			// Cleanup old IPs
			for ip, times := range ipBlockTracker {
				var vBlocks []time.Time
				for _, t := range times {
					if now.Sub(t) < 60*time.Second {
						vBlocks = append(vBlocks, t)
					}
				}
				if len(vBlocks) == 0 {
					delete(ipBlockTracker, ip)
				} else {
					ipBlockTracker[ip] = vBlocks
				}
			}

			ipBlockTracker[clientIP] = validBlocks
			blockCount := len(validBlocks)
			trackerMutex.Unlock()

			if blockCount > 3 {
				log.Printf("TAR-PITTING IP %s for %v\n", clientIP, tarPitDelay)
				time.Sleep(tarPitDelay)
			}
		}

		alertData := map[string]interface{}{
			"event_type": "waf_block",
			"message":    fmt.Sprintf("WAF Blocked %s matching category %s", source, category),
			"details": map[string]interface{}{
				"category":  category,
				"url":       decodedURL,
				"client_ip": clientIP,
				"source":    source,
			},
			"level": "error",
		}

		// Async notification
		go notifyBackend(alertData)

		sendBlockResponse(w, category)
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

	dangerousTypes := []string{"application/x-msdownload", "application/x-dosexec", "application/javascript"}
	isDangerous := false
	for _, dt := range dangerousTypes {
		if strings.Contains(contentTypeLower, dt) {
			isDangerous = true
			break
		}
	}

	if isDangerous {
		log.Printf("Inspecting RESPMOD payload for type: %s\n", contentType)
		// For now, allow. Real AV would block here.
	}

	w.WriteHeader(204, nil, false)
}

func sendBlockResponse(w icap.ResponseWriter, category string) {
	body := fmt.Sprintf(`<html><body><h1>403 Forbidden - Blocked by WAF</h1><p>Your request contains prohibited content. Category: <b>%s</b></p></body></html>`, category)

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

	// HTTP health endpoint for Docker healthcheck
	go func() {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"healthy"}`))
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
