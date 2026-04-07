package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-icap/icap"
)

const (
	maxBodyInspectSize = 1 << 20 // 1 MB
	maxNotifyWorkers   = 8       // Bounded goroutine pool for backend notifications
)

// ── Configuration ───────────────────────────────────────────────────────────

var (
	blockThreshold = 10 // Configurable via WAF_BLOCK_THRESHOLD env
	tarPitDelay    = 10 * time.Second
	ipBlockTracker = make(map[string][]time.Time)
	trackerMutex   sync.Mutex

	// Bounded notification channel — circuit breaker for backend alerts
	notifyChan    = make(chan map[string]interface{}, 64)
	notifyDropped atomic.Int64

	// Safe URL cache — URLs scanned and found clean skip regex on repeat visits.
	// 50K entries, 5 min TTL. Saves ~80% CPU on repetitive traffic.
	safeCache = NewSafeURLCache(50000, 5*time.Minute)
)

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
			if len(line) > 512 {
				log.Printf("Custom rule %d skipped: exceeds 512 char limit\n", i+1)
				continue
			}
			if strings.ContainsRune(line, 0) {
				log.Printf("Custom rule %d skipped: contains null byte\n", i+1)
				continue
			}
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

// disabledCategories tracks which WAF rule categories are turned off.
var (
	disabledCatMu sync.RWMutex
	disabledCats  = map[string]bool{}
)

func isCategoryEnabled(cat string) bool {
	disabledCatMu.RLock()
	defer disabledCatMu.RUnlock()
	return !disabledCats[cat]
}

func init() {
	if envThreshold := os.Getenv("WAF_BLOCK_THRESHOLD"); envThreshold != "" {
		if v, err := strconv.Atoi(envThreshold); err == nil && v > 0 {
			blockThreshold = v
		}
	}
	// Load disabled categories from env (comma-separated)
	if disabled := os.Getenv("WAF_DISABLED_CATEGORIES"); disabled != "" {
		for _, cat := range strings.Split(disabled, ",") {
			cat = strings.TrimSpace(cat)
			if cat != "" {
				disabledCats[cat] = true
			}
		}
		log.Printf("Disabled WAF categories: %v\n", disabled)
	}

	loadCustomRules()
	initHeuristics()

	// Log rule counts
	total := 0
	for _, cr := range blockRules {
		total += len(cr.Rules)
	}
	log.Printf("WAF engine initialized: %d regex rules + 7 heuristic checks across %d categories (block threshold: %d)\n",
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

func handleReqmod(w icap.ResponseWriter, req *icap.Request) {
	if req.Request == nil || req.Request.URL == nil {
		w.WriteHeader(204, nil, false)
		return
	}

	startTime := time.Now()

	rawURL := req.Request.URL.String()

	// Skip WAF inspection for LAN destinations (proxy UI, backend, local services)
	// These are legitimate internal traffic, not SSRF attempts
	host := req.Request.Host
	if isLANHost(host) {
		w.WriteHeader(204, nil, false)
		return
	}

	// ── Safe URL Cache: skip regex scan for known-clean URLs ────────────
	if safeCache.IsSafe(rawURL) {
		w.WriteHeader(204, nil, false)
		return
	}

	normalizedURL := normalizeInput(rawURL)

	// Also check request headers for injection (Log4Shell, SSRF)
	var headerStr string
	headerCount := 0
	for _, hdr := range []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "Accept", "Cookie"} {
		if v := req.Request.Header.Get(hdr); v != "" {
			headerStr += " " + v
			headerCount++
		}
	}
	normalizedHeaders := normalizeInput(headerStr)

	// Combine URL + headers for scoring
	combined := normalizedURL + " " + normalizedHeaders
	matches, score := matchRulesScored(combined)

	// Also check raw (pre-decoded) URL for encoded evasion patterns like %c0%af
	// that get decoded by normalizeInput and lose their detectable pattern
	if score < blockThreshold && rawURL != normalizedURL {
		rawMatches, rawScore := matchRulesScored(rawURL)
		if rawScore > 0 {
			matches = append(matches, rawMatches...)
			score += rawScore
		}
	}

	// Check request body if score not yet over threshold
	var bodyStr string
	var bodySize int
	if score < blockThreshold && req.Request.Body != nil {
		ct := req.Request.Header.Get("Content-Type")
		if isTextContent(ct) {
			bodyBytes, readErr := io.ReadAll(io.LimitReader(req.Request.Body, maxBodyInspectSize))
			if readErr == nil && len(bodyBytes) > 0 {
				bodyStr = normalizeInput(string(bodyBytes))
				bodySize = len(bodyBytes)
				req.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				bodyMatches, bodyScore := matchRulesScored(bodyStr)
				matches = append(matches, bodyMatches...)
				score += bodyScore
			}
		}
	}

	// ── ML-lite: DGA + Typosquatting detection ─────────────────────────
	if score < blockThreshold && host != "" {
		// DGA detection — domains generated by malware algorithms
		dgaResult := AnalyzeDGA(host)
		if dgaResult.IsDGA {
			matches = append(matches, MatchResult{
				RuleID:   "ML-DGA-001",
				Category: "DGA_DOMAIN",
				Score:    10,
			})
			score += 10
			log.Printf("WAF ML-DGA score=%d domain=%s dga_score=%d\n", dgaResult.Score, host, dgaResult.Score)
		}

		// Typosquatting detection — domains impersonating known brands
		typoResult := CheckTyposquat(host)
		if typoResult.Suspicious {
			matches = append(matches, MatchResult{
				RuleID:   "ML-TYPO-001",
				Category: "TYPOSQUATTING",
				Score:    10,
			})
			score += 10
			log.Printf("WAF ML-TYPO target=%s technique=%s distance=%d domain=%s\n",
				typoResult.Target, typoResult.Technique, typoResult.Distance, host)
		}
	}

	// ── Feature extraction ──────────────────────────────────────────────
	clientIP := "unknown"
	if ipHeaders := req.Header.Values("X-Client-Ip"); len(ipHeaders) > 0 {
		if parsed := net.ParseIP(strings.TrimSpace(ipHeaders[0])); parsed != nil {
			clientIP = parsed.String()
		}
	}

	ruleIDs := make([]string, len(matches))
	categories := make([]string, 0)
	catSet := make(map[string]bool)
	for i, m := range matches {
		ruleIDs[i] = m.RuleID
		if !catSet[m.Category] {
			categories = append(categories, m.Category)
			catSet[m.Category] = true
		}
	}

	action := "allow"
	if score >= blockThreshold {
		action = "block"
	}

	feature := TrafficFeature{
		Timestamp:       startTime.UTC().Format(time.RFC3339),
		ClientIP:        clientIP,
		Method:          req.Request.Method,
		Host:            req.Request.Host,
		Path:            req.Request.URL.Path,
		URLLength:       len(rawURL),
		URLEntropy:      shannonEntropy(rawURL),
		QueryParamCount: len(req.Request.URL.Query()),
		BodySize:        bodySize,
		BodyEntropy:     shannonEntropy(bodyStr),
		ContentType:     req.Request.Header.Get("Content-Type"),
		HeaderCount:     headerCount,
		UserAgent:       req.Request.Header.Get("User-Agent"),
		IsTLS:           req.Request.URL.Scheme == "https",
		DestPort:        req.Request.URL.Port(),
		WAFScore:        score,
		WAFRules:        ruleIDs,
		Action:          action,
		LatencyUS:       time.Since(startTime).Microseconds(),
	}

	// ── Behavioral heuristics (stateful, time-windowed) ────────────────
	var rawHdrs string
	for k, vals := range req.Request.Header {
		for _, v := range vals {
			rawHdrs += k + ": " + v + "\n"
		}
	}
	hResults, hScore := CheckRequestHeuristics(
		clientIP, req.Request.Method, req.Request.Host, req.Request.URL.Path,
		bodyStr, rawHdrs, bodySize, feature.BodyEntropy, feature.URLEntropy,
	)
	for _, hr := range hResults {
		matches = append(matches, MatchResult{
			Category: hr.Category,
			RuleID:   hr.ID,
			Pattern:  hr.Detail,
			Score:    hr.Score,
		})
		ruleIDs = append(ruleIDs, hr.ID)
		if !catSet[hr.Category] {
			categories = append(categories, hr.Category)
			catSet[hr.Category] = true
		}
	}
	score += hScore
	if score >= blockThreshold {
		action = "block"
	}
	feature.WAFScore = score
	feature.WAFRules = ruleIDs
	feature.Action = action

	// Non-blocking: Write() enqueues to bounded channel, record() uses atomics
	trafficLog.Write(feature)
	stats.record(feature, score >= blockThreshold, categories)

	// Log all matches for observability, even if below threshold
	if len(matches) > 0 && score < blockThreshold {
		log.Printf("WAF OBSERVE score=%d/%d rules=[%s] url=%s\n",
			score, blockThreshold, strings.Join(ruleIDs, ","), truncate(rawURL, 200))
	}

	// Block if score meets threshold
	if score >= blockThreshold {
		source := "URL"
		if bodyStr != "" {
			source = "URL+BODY"
		}
		primaryCategory := "UNKNOWN"
		if len(categories) > 0 {
			primaryCategory = categories[0]
		}

		log.Printf("WAF BLOCKED score=%d/%d categories=[%s] rules=[%s] source=%s url=%s\n",
			score, blockThreshold, strings.Join(categories, ","), strings.Join(ruleIDs, ","),
			source, truncate(rawURL, 200))

		// Tar-pitting for repeat offenders
		if clientIP != "unknown" {
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
			"message":    fmt.Sprintf("WAF blocked %s — score %d, categories: %s", source, score, strings.Join(categories, ", ")),
			"details": map[string]interface{}{
				"category":   primaryCategory,
				"categories": categories,
				"rules":      ruleIDs,
				"score":      score,
				"threshold":  blockThreshold,
				"url":        truncate(rawURL, 500),
				"client_ip":  clientIP,
				"source":     source,
			},
			"level": "error",
		}
		// Non-blocking enqueue — drops if backend can't keep up (circuit breaker)
		select {
		case notifyChan <- alertData:
		default:
			notifyDropped.Add(1)
		}

		sendBlockResponse(w, primaryCategory, score)
		return
	}

	// URL passed all checks — mark as safe for future requests
	safeCache.MarkSafe(rawURL)
	w.WriteHeader(204, nil, false)
}

func handleRespmod(w icap.ResponseWriter, req *icap.Request) {
	if req.Response == nil {
		w.WriteHeader(204, nil, false)
		return
	}

	contentType := req.Response.Header.Get("Content-Type")
	contentTypeLower := strings.ToLower(contentType)

	// Block dangerous binary content types
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

	// Inspect text response bodies for reflected XSS and secret leaks
	if req.Response.Body != nil && isTextContent(contentType) {
		bodyBytes, err := io.ReadAll(io.LimitReader(req.Response.Body, maxBodyInspectSize))
		if err == nil && len(bodyBytes) > 0 {
			req.Response.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			body := string(bodyBytes)
			totalScore := 0
			var matchedRules []string
			var matchedCat string
			for _, cr := range respRules {
				if !isCategoryEnabled(cr.Category) {
					continue
				}
				for _, rule := range cr.Rules {
					if rule.Pattern.MatchString(body) {
						totalScore += rule.Severity
						matchedRules = append(matchedRules, rule.ID)
						if matchedCat == "" {
							matchedCat = cr.Category
						}
					}
				}
			}
			// H3: PII counter heuristic on response body
			piiResults, piiScore := CheckResponseHeuristics(body)
			for _, pr := range piiResults {
				totalScore += pr.Score
				matchedRules = append(matchedRules, pr.ID)
				if matchedCat == "" {
					matchedCat = pr.Category
				}
			}

			if totalScore >= blockThreshold {
				log.Printf("RESPMOD BLOCKED score=%d rules=[%s] content-type=%s\n",
					totalScore, strings.Join(matchedRules, ","), contentType)
				sendBlockResponse(w, matchedCat, totalScore)
				return
			}
			_ = piiScore
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

	// Initialize traffic logger (async via bounded channel)
	trafficLog = newTrafficLogger(trafficLogPath, trafficLogMaxBytes)
	if trafficLog != nil {
		log.Printf("Traffic logging to %s (max %dMB, queue=%d)\n",
			trafficLogPath, trafficLogMaxBytes/(1<<20), logQueueSize)
		go func() {
			for {
				time.Sleep(5 * time.Second)
				trafficLog.Flush()
			}
		}()
	}

	// Start bounded notification worker pool (circuit breaker pattern)
	for i := 0; i < maxNotifyWorkers; i++ {
		go func() {
			for data := range notifyChan {
				notifyBackend(data)
			}
		}()
	}
	log.Printf("Notification worker pool: %d workers, queue=%d\n", maxNotifyWorkers, cap(notifyChan))

	// Periodic cleanup of ipBlockTracker (prevents unbounded growth from drive-by IPs)
	go func() {
		for {
			time.Sleep(30 * time.Second)
			trackerMutex.Lock()
			now := time.Now()
			for ip, times := range ipBlockTracker {
				var valid []time.Time
				for _, t := range times {
					if now.Sub(t) < 60*time.Second {
						valid = append(valid, t)
					}
				}
				if len(valid) == 0 {
					delete(ipBlockTracker, ip)
				} else {
					ipBlockTracker[ip] = valid
				}
			}
			trackerMutex.Unlock()
		}
	}()

	// Start stats recent counter reset
	stats.startRecentCounter()

	// Periodic client state cleanup (heuristics)
	go func() {
		for {
			time.Sleep(60 * time.Second)
			cleanupClientStates()
		}
	}()

	// HTTP health + metrics endpoint
	go func() {
		h := &MgmtHandlers{}
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", h.HealthHandler)
		healthMux.HandleFunc("/stats", h.StatsHandler)
		healthMux.HandleFunc("/reset", h.ResetHandler)
		healthMux.HandleFunc("/categories", h.CategoriesHandler)
		healthMux.HandleFunc("/categories/toggle", h.CategoriesToggleHandler)

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

// ── Management Handlers ─────────────────────────────────────────────────────

type MgmtHandlers struct{}

func (h *MgmtHandlers) HealthHandler(w http.ResponseWriter, r *http.Request) {
	total := 0
	for _, cr := range blockRules {
		total += len(cr.Rules)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	hEnabled := 0
	for _, on := range []bool{heuristicCfg.EntropyThreshold, heuristicCfg.BeaconingDetection, heuristicCfg.PIICounter, heuristicCfg.DestinationSharding, heuristicCfg.HeaderMorphing, heuristicCfg.ProtocolGhosting, heuristicCfg.SequenceValidation} {
		if on {
			hEnabled++
		}
	}
	fmt.Fprintf(w, `{"status":"healthy","rules":%d,"categories":%d,"threshold":%d,"heuristics":%d}`,
		total, len(blockRules), blockThreshold, hEnabled)
}

func (h *MgmtHandlers) StatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	snap := stats.snapshot()
	// Merge cache stats
	for k, v := range safeCache.Stats() {
		snap[k] = v
	}
	json.NewEncoder(w).Encode(snap)
}

func (h *MgmtHandlers) ResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	stats.reset()
	safeCache.Invalidate()
	log.Println("WAF stats + safe cache reset via API")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","message":"stats reset"}`))
}

func (h *MgmtHandlers) CategoriesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	type catInfo struct {
		Name    string `json:"name"`
		Rules   int    `json:"rules"`
		Enabled bool   `json:"enabled"`
	}
	disabledCatMu.RLock()
	var cats []catInfo
	for _, cr := range blockRules {
		cats = append(cats, catInfo{
			Name:    cr.Category,
			Rules:   len(cr.Rules),
			Enabled: !disabledCats[cr.Category],
		})
	}
	disabledCatMu.RUnlock()
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": cats})
}

func (h *MgmtHandlers) CategoriesToggleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Category string `json:"category"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Category == "" {
		http.Error(w, `{"error":"category required"}`, 400)
		return
	}
	disabledCatMu.Lock()
	if req.Enabled {
		delete(disabledCats, req.Category)
	} else {
		disabledCats[req.Category] = true
	}
	disabledCatMu.Unlock()
	safeCache.Invalidate() // Clear cache since rules changed
	log.Printf("Category %s: enabled=%v\n", req.Category, req.Enabled)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","category":"%s","enabled":%v}`, req.Category, req.Enabled)
}
