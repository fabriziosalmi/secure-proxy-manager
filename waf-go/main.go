package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-icap/icap"

	"secure-proxy-waf/internal/engine"
)

const (
	maxBodyInspectSize = 1 << 20 // 1 MB
	maxNotifyWorkers   = 8       // Bounded goroutine pool for backend notifications
)

// ── Configuration ───────────────────────────────────────────────────────────

var (
	// wafFailOpen controls behaviour when a REQMOD handler panics. Default is
	// fail-CLOSED (block the request) — a handler that crashed cannot vouch for
	// traffic. Operators who prefer availability over inspection can set
	// WAF_FAIL_OPEN=1 to let such requests through unmodified.
	wafFailOpen = false

	tarPitDelay    = 10 * time.Second
	ipBlockTracker = make(map[string][]time.Time)
	trackerMutex   sync.Mutex

	// Bounded notification channel — circuit breaker for backend alerts
	notifyChan    = make(chan map[string]interface{}, 64)
	notifyDropped atomic.Int64

	// bodyTruncatedCount counts requests whose body exceeded maxBodyInspectSize,
	// so only a 1 MB prefix was scanned. Surfaced via /metrics so the coverage
	// gap (payload hidden behind >1 MB of padding) is observable, not silent.
	bodyTruncatedCount atomic.Int64

	// respmodUninspectable counts text responses the WAF could NOT actually scan
	// because the body was compressed (Content-Encoding gzip/br/deflate) — the
	// regex rules would only see compressed bytes. Surfaced so operators know
	// response-side coverage has a hole rather than assuming everything was clean.
	respmodUninspectable atomic.Int64

	// Reusable HTTP client for backend notifications (avoid alloc per call)
	notifyClient = &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     60 * time.Second,
	}}
)

// ── ICAP ISTag (RFC 3507 §4.7) ───────────────────────────────────────────────
// Squid uses the ISTag to decide whether a cached ICAP verdict is still valid.
// It MUST change whenever the effective ruleset changes, otherwise Squid may
// keep serving stale allow/block decisions after a rule reload or a category
// toggle. We derive a stable base from the loaded rules + the startup disabled
// set, and bump an atomic epoch on every runtime change (no lock on the hot
// path). The value is emitted on OPTIONS and every REQMOD/RESPMOD response.
var (
	istagBase  string // 16-hex digest of the rules + startup-disabled categories
	istagEpoch uint64 // bumped on every runtime ruleset change (category toggle)
)

// initISTag must run after loadCustomRules() and after the env-disabled set is
// populated, so both are folded into the base digest.
func initISTag() {
	h := sha256.New()
	for _, cr := range engine.BlockRules() {
		fmt.Fprintf(h, "C:%s\n", cr.Category)
		for _, r := range cr.Rules {
			fmt.Fprintf(h, "R:%s:%d:%d\n", r.ID, r.Severity, r.Tier)
		}
	}
	// Fold the startup disabled set so a different WAF_DISABLED_CATEGORIES env
	// yields a different ISTag across restarts. The set arrives sorted: it used
	// to be folded in Go map order, so two restarts with the same configuration
	// could publish different ISTags and needlessly invalidate Squid's cache.
	for _, cat := range eng.DisabledCategories() {
		fmt.Fprintf(h, "D:%s\n", cat)
	}
	istagBase = hex.EncodeToString(h.Sum(nil))[:16]
}

// currentISTag returns the quoted ISTag for the current effective ruleset.
func currentISTag() string {
	return `"` + istagBase + "-" + strconv.FormatUint(atomic.LoadUint64(&istagEpoch), 36) + `"`
}

// eng is the WAF's detection engine: the single wire from this composition root
// into internal/engine. Everything that decides whether a request is refused —
// the threshold, the rule categories, the safe-URL cache, the heuristic config
// and its per-client history — lives behind it, and can only be reached through
// its methods (SECURE-ARCH-03). This file is the ICAP transport.
var eng *engine.Engine

// engineConfigFromEnv reads the operator's environment into the engine's
// configuration: the score at which a request is refused, the categories
// switched off at startup, and the heuristic toggles.
func engineConfigFromEnv() engine.Config {
	cfg := engine.Config{Heuristics: engine.HeuristicsFromEnv()}
	if envThreshold := os.Getenv("WAF_BLOCK_THRESHOLD"); envThreshold != "" {
		if v, err := strconv.Atoi(envThreshold); err == nil && v > 0 {
			cfg.BlockThreshold = v
		}
	}
	if disabled := os.Getenv("WAF_DISABLED_CATEGORIES"); disabled != "" {
		for _, cat := range strings.Split(disabled, ",") {
			if cat = strings.TrimSpace(cat); cat != "" {
				cfg.DisabledCategories = append(cfg.DisabledCategories, cat)
			}
		}
		log.Printf("Disabled WAF categories: %v\n", disabled)
	}
	return cfg
}

func init() {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WAF_FAIL_OPEN"))) {
	case "1", "true", "yes", "on":
		wafFailOpen = true
		log.Printf("WAF_FAIL_OPEN=1 — REQMOD handler panics will ALLOW traffic (availability over security)\n")
	}

	// Rules first: the pre-filter gates the custom rules too (#110), and the
	// ISTag digest must cover the set actually loaded.
	engine.LoadCustomRules(engine.DefaultCustomRulesPath)
	engine.BuildPrefilter()
	eng = engine.New(engineConfigFromEnv())
	initISTag()

	total := 0
	for _, cr := range engine.BlockRules() {
		total += len(cr.Rules)
	}
	log.Printf("WAF engine initialized: %d regex rules + 7 heuristic checks across %d categories (block threshold: %d)\n",
		total, len(engine.BlockRules()), eng.BlockThreshold())
}

// ── Backend notification ────────────────────────────────────────────────────

// warnNoAlertCredential logs at most once a minute. notifyBackend is called on
// every block, so an unconfigured deployment under attack would otherwise turn
// its own log into the flood.
var lastCredWarn atomic.Int64

func warnNoAlertCredential() {
	now := time.Now().Unix()
	prev := lastCredWarn.Load()
	if now-prev < 60 || !lastCredWarn.CompareAndSwap(prev, now) {
		return
	}
	log.Printf("no backend alert credential: set INTERNAL_ALERT_TOKEN (openssl rand -hex 32) " +
		"on both the waf and backend services; alerts are being dropped\n")
}

func notifyBackend(data map[string]interface{}) {
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://backend:5000"
	}
	// A dedicated token scoped to /api/internal/alert is the supported way to
	// authenticate here. The WAF used to send BASIC_AUTH_USERNAME/PASSWORD —
	// the admin credential — so this process, the one that parses
	// attacker-controlled request bodies, could drive every administrative
	// endpoint on the backend (SECURE-AUTH-02).
	//
	// The basic-auth path is kept only as a fallback for deployments upgrading
	// with a hand-written compose file that still passes BASIC_AUTH_* here. The
	// shipped compose files no longer do.
	alertToken := strings.TrimSpace(os.Getenv("INTERNAL_ALERT_TOKEN"))
	authUser := os.Getenv("BASIC_AUTH_USERNAME")
	authPass := os.Getenv("BASIC_AUTH_PASSWORD")
	if alertToken == "" && (authUser == "" || authPass == "") {
		warnNoAlertCredential()
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

	if alertToken != "" {
		req.Header.Set("Authorization", "Bearer "+alertToken)
	} else {
		req.SetBasicAuth(authUser, authPass)
	}
	req.Header.Set("Content-Type", "application/json")

	client := notifyClient
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

// recoverICAP turns a handler panic into a deterministic ICAP response instead
// of a dropped connection (whose effect depends on Squid's bypass setting and
// is typically fail-OPEN). For REQMOD it fails CLOSED by default — a crashed
// handler cannot certify the request as clean — unless WAF_FAIL_OPEN is set.
// RESPMOD failures allow the response through (blocking responses on an internal
// error is riskier than letting them pass). It is invoked via defer, so it only
// fires before a normal WriteHeader has run.
func recoverICAP(w icap.ResponseWriter, method string) {
	if r := recover(); r != nil {
		log.Printf("PANIC in %s handler: %v\n%s", method, r, debug.Stack())
		if method == "REQMOD" && !wafFailOpen {
			sendBlockResponse(w, "WAF_INTERNAL_ERROR", eng.BlockThreshold(), "")
			return
		}
		w.WriteHeader(204, nil, false)
	}
}

func handleOptions(w icap.ResponseWriter, req *icap.Request) {
	w.Header().Set("ISTag", currentISTag())
	w.Header().Set("Methods", "REQMOD, RESPMOD")
	w.Header().Set("Service", "SecureProxy-WAF-2.0")
	w.Header().Set("Preview", "1024")
	w.Header().Set("Transfer-Preview", "*")
	w.Header().Set("Transfer-Ignore", "jpg,jpeg,gif,png,swf,flv,mp4,webm,woff2")
	w.Header().Set("Transfer-Complete", "")
	w.Header().Set("Max-Connections", "100")
	w.WriteHeader(200, nil, false)
}

var eventCounter uint64

// nextEventID returns a process-unique, time-ordered correlation ID for one
// inspected request: base-36 nanos + an atomic counter. Cheap on the
// latency-tracked hot path (no crypto/rand). It ties a block's WAF traffic-log
// record to the notification/websocket event the backend emits for it.
func nextEventID(t time.Time) string {
	n := atomic.AddUint64(&eventCounter, 1)
	return strconv.FormatInt(t.UnixNano(), 36) + "-" + strconv.FormatUint(n, 36)
}

// inspection accumulates everything one REQMOD pass learns about a request.
// It exists so the stages below can be separate functions that still share the
// running score: handleReqmod used to be a single 226-line body at cyclomatic
// complexity 48, on the hottest path in the product, with no seam a test could
// reach (SECURE-QUAL-02).
type inspection struct {
	eventID   string
	startTime time.Time

	rawURL   string
	clientIP string

	// Accumulated signals. score is the sum of every match's Score, and the
	// block decision is Blocked(score) — checked once, at the end.
	matches []engine.MatchResult
	score   int

	// Body inspection results, needed later for the traffic feature and to
	// decide whether a clean verdict may be cached.
	bodyStr  string
	bodySize int

	headerCount int

	// Safe-URL cache addressing, computed once up front and reused at the end.
	cacheable bool
	cacheKey  string
}

// blocked reports the verdict. Every stage adds to score; nothing else decides.
func (in *inspection) blocked() bool { return eng.Blocked(in.score) }

// add records a signal and its contribution to the score.
func (in *inspection) add(m engine.MatchResult) {
	in.matches = append(in.matches, m)
	in.score += m.Score
}

func handleReqmod(w icap.ResponseWriter, req *icap.Request) {
	w.Header().Set("ISTag", currentISTag())
	if req.Request == nil || req.Request.URL == nil {
		w.WriteHeader(204, nil, false)
		return
	}

	startTime := time.Now()
	defer func() { reqmodLatency.Observe(time.Since(startTime)) }()

	in := &inspection{
		eventID:   nextEventID(startTime),
		startTime: startTime,
		rawURL:    req.Request.URL.String(),
		clientIP:  clientIPFrom(req),
	}

	// Skip WAF inspection for LAN destinations (proxy UI, backend, local
	// services). These are legitimate internal traffic, not SSRF attempts.
	if engine.IsLANHost(req.Request.Host) {
		w.WriteHeader(204, nil, false)
		return
	}

	// ── Safe URL Cache: skip regex scan for known-clean URLs ────────────
	// Only short-circuit idempotent, body-less methods, and scope the cache key
	// by method. A clean GET must never vouch for a POST to the same URL — that
	// request carries an attacker-controlled body and headers we have not seen
	// (the previous rawURL-only key let a benign GET poison the cache so a later
	// malicious POST skipped ALL inspection).
	in.cacheable = req.Request.Method == http.MethodGet || req.Request.Method == http.MethodHead
	in.cacheKey = req.Request.Method + "\x00" + in.rawURL
	if in.cacheable && eng.SafeCache().IsSafe(in.cacheKey) {
		w.WriteHeader(204, nil, false)
		return
	}

	scanSignatures(in, req.Request)
	scanDomainReputation(in, req.Request.Host)

	feature := in.feature(req.Request)
	applyHeuristics(in, req.Request, &feature)

	ruleIDs, categories := summarize(in.matches)
	feature.WAFScore = in.score
	feature.WAFRules = ruleIDs
	feature.Action = "allow"
	if in.blocked() {
		feature.Action = "block"
	}

	// Non-blocking: Write() enqueues to bounded channel, record() uses atomics
	trafficLog.Write(feature)
	stats.record(feature, in.blocked(), categories)

	// Log all matches for observability, even if below threshold
	if len(in.matches) > 0 && !in.blocked() {
		log.Printf("WAF OBSERVE score=%d/%d rules=[%s] url=%q\n",
			in.score, eng.BlockThreshold(), strings.Join(ruleIDs, ","), truncate(in.rawURL, 200))
	}

	if in.blocked() {
		block(w, in, ruleIDs, categories)
		return
	}

	// URL passed all checks — mark as safe for future requests. Only cache a
	// clean verdict for body-less idempotent methods where no body was inspected,
	// so a pass can never authorize a later request that carries a body.
	if in.cacheable && in.bodySize == 0 {
		eng.SafeCache().MarkSafe(in.cacheKey)
	}
	w.WriteHeader(204, nil, false)
}

// clientIPFrom reads the address Squid stamped on the ICAP request. Anything
// that does not parse as an IP is reported as "unknown" rather than echoed,
// so an attacker-controlled value cannot reach the logs or the tar-pit map.
func clientIPFrom(req *icap.Request) string {
	if ipHeaders := req.Header.Values("X-Client-Ip"); len(ipHeaders) > 0 {
		if parsed := net.ParseIP(strings.TrimSpace(ipHeaders[0])); parsed != nil {
			return parsed.String()
		}
	}
	return "unknown"
}

// headersToInspect are the request headers scanned for injection payloads
// (Log4Shell, SSRF). Kept as a package-level list so the set is one thing to
// audit rather than a literal buried in the hot path.
var headersToInspect = []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "Accept", "Cookie"}

// scanSignatures runs the regex rule set over the URL, the inspected headers
// and — if nothing has crossed the threshold yet — the request body.
func scanSignatures(in *inspection, r *http.Request) {
	normalizedURL := engine.NormalizeInput(in.rawURL)

	var headerStr string
	for _, hdr := range headersToInspect {
		if v := r.Header.Get(hdr); v != "" {
			headerStr += " " + v
			in.headerCount++
		}
	}

	// Combine URL + headers for scoring
	combined := normalizedURL + " " + engine.NormalizeInput(headerStr)
	matches, score := eng.MatchRulesScored(combined)
	in.matches = append(in.matches, matches...)
	in.score += score

	// Also check raw (pre-decoded) URL for encoded evasion patterns like %c0%af
	// that get decoded by engine.NormalizeInput and lose their detectable pattern
	if !in.blocked() && in.rawURL != normalizedURL {
		rawMatches, rawScore := eng.MatchRulesScored(in.rawURL)
		if rawScore > 0 {
			in.matches = append(in.matches, rawMatches...)
			in.score += rawScore
		}
	}

	if !in.blocked() {
		scanBody(in, r)
	}
}

// scanBody inspects the request body, up to maxBodyInspectSize, and restores it
// so the request can still be forwarded. Bodies of types the rule set cannot
// meaningfully match are skipped.
func scanBody(in *inspection, r *http.Request) {
	if r.Body == nil || !engine.ShouldInspectBody(r.Header.Get("Content-Type")) {
		return
	}
	// Read one byte past the inspection limit so we can tell whether the body
	// was truncated (i.e. a payload may be hiding past the limit).
	bodyBytes, readErr := io.ReadAll(io.LimitReader(r.Body, maxBodyInspectSize+1))
	if readErr != nil || len(bodyBytes) == 0 {
		return
	}
	truncated := len(bodyBytes) > maxBodyInspectSize
	if truncated {
		bodyBytes = bodyBytes[:maxBodyInspectSize]
	}
	in.bodyStr = engine.NormalizeInput(string(bodyBytes))
	in.bodySize = len(bodyBytes)
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	bodyMatches, bodyScore := eng.MatchRulesScored(in.bodyStr)
	in.matches = append(in.matches, bodyMatches...)
	in.score += bodyScore

	// An over-limit body is a coverage gap, not a clean allow. Add a
	// corroborating signal (below the block threshold, so it can't block on its
	// own — pairs with any other rule/heuristic hit) and count it.
	if truncated {
		bodyTruncatedCount.Add(1)
		const oversizeBodyScore = 4
		in.add(engine.MatchResult{RuleID: "WAF-BODY-OVERSIZE", Category: "BODY_OVERSIZE", Score: oversizeBodyScore})
	}
}

// scanDomainReputation applies the ML-lite signals: DGA and typosquatting.
//
// Both are probabilistic, so each contributes LESS than the block threshold and
// cannot block on its own — corroboration from another signal or a signature
// rule is required. That is what keeps a typosquat near-miss on a real domain
// observed rather than blocked.
func scanDomainReputation(in *inspection, host string) {
	if in.blocked() || host == "" {
		return
	}
	const dgaScore, typoScore = 6, 5

	if eng.CategoryEnabled("DGA_DOMAIN") {
		if dgaResult := eng.AnalyzeDGACached(host); dgaResult.IsDGA {
			in.add(engine.MatchResult{RuleID: "ML-DGA-001", Category: "DGA_DOMAIN", Score: dgaScore})
			// %q quotes + escapes control bytes so an attacker-controlled Host
			// header (newline, tab, ANSI escapes) cannot forge log entries.
			log.Printf("WAF ML-DGA score=%d domain=%q dga_score=%d\n", dgaResult.Score, host, dgaResult.Score)
		}
	}
	if eng.CategoryEnabled("TYPOSQUATTING") {
		if typoResult := engine.CheckTyposquat(host); typoResult.Suspicious {
			in.add(engine.MatchResult{RuleID: "ML-TYPO-001", Category: "TYPOSQUATTING", Score: typoScore})
			log.Printf("WAF ML-TYPO target=%q technique=%q distance=%d domain=%q\n",
				typoResult.Target, typoResult.Technique, typoResult.Distance, host)
		}
	}
}

// feature builds the traffic record for this request. The score and action it
// carries are provisional: the heuristics run against its entropy fields, so
// they are recomputed by the caller once those have contributed.
func (in *inspection) feature(r *http.Request) TrafficFeature {
	ruleIDs, _ := summarize(in.matches)
	action := "allow"
	if in.blocked() {
		action = "block"
	}
	return TrafficFeature{
		EventID:         in.eventID,
		Timestamp:       in.startTime.UTC().Format(time.RFC3339),
		ClientIP:        in.clientIP,
		Method:          r.Method,
		Host:            r.Host,
		Path:            r.URL.Path,
		URLLength:       len(in.rawURL),
		URLEntropy:      engine.ShannonEntropy(in.rawURL),
		QueryParamCount: len(r.URL.Query()),
		BodySize:        in.bodySize,
		BodyEntropy:     engine.ShannonEntropy(in.bodyStr),
		ContentType:     r.Header.Get("Content-Type"),
		HeaderCount:     in.headerCount,
		UserAgent:       r.Header.Get("User-Agent"),
		IsTLS:           r.URL.Scheme == "https",
		DestPort:        r.URL.Port(),
		WAFScore:        in.score,
		WAFRules:        ruleIDs,
		Action:          action,
		LatencyUS:       time.Since(in.startTime).Microseconds(),
	}
}

// applyHeuristics runs the stateful, time-windowed behavioural checks. They are
// scored against the feature's entropy fields, which is why they run after it
// is built rather than alongside the signature scan.
func applyHeuristics(in *inspection, r *http.Request, feature *TrafficFeature) {
	hResults, hScore := eng.CheckRequestHeuristics(
		in.clientIP, r.Method, r.Host, r.URL.Path,
		in.bodyStr, in.bodySize, feature.BodyEntropy, feature.URLEntropy,
	)
	for _, hr := range hResults {
		in.matches = append(in.matches, engine.MatchResult{
			Category: hr.Category,
			RuleID:   hr.ID,
			Pattern:  hr.Detail,
			Score:    hr.Score,
		})
	}
	// The returned total is used rather than re-summing the results. It is the
	// same number today — every heuristic that appends a result also adds its
	// score — but taking the function at its word keeps this independent of
	// that internal detail.
	in.score += hScore
}

// summarize flattens the matches into the rule IDs and the de-duplicated
// categories, preserving first-seen order — the first category is what the
// block page and the alert report as the primary one.
func summarize(matches []engine.MatchResult) (ruleIDs, categories []string) {
	ruleIDs = make([]string, len(matches))
	categories = make([]string, 0)
	seen := make(map[string]bool, len(matches))
	for i, m := range matches {
		ruleIDs[i] = m.RuleID
		if !seen[m.Category] {
			categories = append(categories, m.Category)
			seen[m.Category] = true
		}
	}
	return ruleIDs, categories
}

// block logs the decision, applies the tar-pit to repeat offenders, notifies
// the backend and writes the block page.
func block(w icap.ResponseWriter, in *inspection, ruleIDs, categories []string) {
	source := "URL"
	if in.bodyStr != "" {
		source = "URL+BODY"
	}
	primaryCategory := "UNKNOWN"
	if len(categories) > 0 {
		primaryCategory = categories[0]
	}

	log.Printf("WAF BLOCKED score=%d/%d categories=[%s] rules=[%s] source=%s url=%q\n",
		in.score, eng.BlockThreshold(), strings.Join(categories, ","), strings.Join(ruleIDs, ","),
		source, truncate(in.rawURL, 200))

	tarPit(in.clientIP)

	alertData := map[string]interface{}{
		"event_type": "waf_block",
		"message":    fmt.Sprintf("WAF blocked %s — score %d, categories: %s", source, in.score, strings.Join(categories, ", ")),
		"details": map[string]interface{}{
			"event_id":   in.eventID,
			"category":   primaryCategory,
			"categories": categories,
			"rules":      ruleIDs,
			"score":      in.score,
			"threshold":  eng.BlockThreshold(),
			"url":        truncate(in.rawURL, 500),
			"client_ip":  in.clientIP,
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

	sendBlockResponse(w, primaryCategory, in.score, in.eventID)
}

// tarPit delays the response to an address that has been blocked repeatedly in
// the last minute, so a scanner pays for each attempt.
func tarPit(clientIP string) {
	if clientIP == "unknown" {
		return
	}
	trackerMutex.Lock()
	now := time.Now()
	var validBlocks []time.Time
	for _, t := range ipBlockTracker[clientIP] {
		if now.Sub(t) < 60*time.Second {
			validBlocks = append(validBlocks, t)
		}
	}
	validBlocks = append(validBlocks, now)

	// Cap tracker size to prevent unbounded growth under DDoS
	if len(ipBlockTracker) > 10000 {
		for ip := range ipBlockTracker {
			if ip != clientIP {
				delete(ipBlockTracker, ip)
				break // remove one stale entry per block event
			}
		}
	}

	ipBlockTracker[clientIP] = validBlocks
	blockCount := len(validBlocks)
	trackerMutex.Unlock()

	if blockCount > 3 {
		log.Printf("TAR-PITTING IP %s (blocks=%d) — delaying response %v\n", clientIP, blockCount, tarPitDelay)
		time.Sleep(tarPitDelay)
		log.Printf("TAR-PIT released for %s\n", clientIP)
	}
}

func handleRespmod(w icap.ResponseWriter, req *icap.Request) {
	w.Header().Set("ISTag", currentISTag())
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
			sendBlockResponse(w, "DANGEROUS_CONTENT_TYPE", 10, "")
			return
		}
	}

	// Compressed text bodies are uninspectable by the regex rules (they'd match
	// against compressed bytes). Flag the coverage gap rather than silently
	// returning a clean verdict. Decompression is deferred to a later phase.
	if req.Response.Body != nil && engine.IsTextContent(contentType) && engine.IsCompressedEncoding(req.Response.Header.Get("Content-Encoding")) {
		respmodUninspectable.Add(1)
		w.WriteHeader(204, nil, false)
		return
	}

	// Inspect text response bodies for reflected XSS and secret leaks
	if req.Response.Body != nil && engine.IsTextContent(contentType) {
		bodyBytes, err := io.ReadAll(io.LimitReader(req.Response.Body, maxBodyInspectSize))
		if err == nil && len(bodyBytes) > 0 {
			req.Response.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			body := string(bodyBytes)
			totalScore, matchedRules, matchedCat := eng.MatchResponseRules(body)
			// H3: PII counter heuristic on response body
			piiResults, piiScore := eng.CheckResponseHeuristics(body)
			for _, pr := range piiResults {
				totalScore += pr.Score
				matchedRules = append(matchedRules, pr.ID)
				if matchedCat == "" {
					matchedCat = pr.Category
				}
			}

			if eng.Blocked(totalScore) {
				log.Printf("RESPMOD BLOCKED score=%d rules=[%s] content-type=%s\n",
					totalScore, strings.Join(matchedRules, ","), contentType)
				sendBlockResponse(w, matchedCat, totalScore, "")
				return
			}
			_ = piiScore
		}
	}

	w.WriteHeader(204, nil, false)
}

// sendBlockResponse encapsulates a 403 in the ICAP reply. When eventID is
// non-empty it is stamped on the response as X-WAF-Event-Id so the same
// correlation ID that lands in the WAF traffic log + notification can be picked
// up by Squid's access log (custom `spm` logformat) and joined to the
// proxy_logs row end-to-end (issue #107).
func sendBlockResponse(w icap.ResponseWriter, category string, score int, eventID string) {
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
	if eventID != "" {
		resp.Header.Set("X-WAF-Event-Id", eventID)
	}
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
			defer recoverICAP(w, "REQMOD")
			handleReqmod(w, req)
		case "RESPMOD":
			defer recoverICAP(w, "RESPMOD")
			handleRespmod(w, req)
		default:
			w.WriteHeader(405, nil, false)
		}
	})

	// Initialize traffic logger (async via bounded channel)
	trafficLog = newTrafficLogger(trafficLogPath, trafficLogMaxBytes)
	if trafficLog != nil {
		// Report the path actually in use (may be the /tmp fallback), not the const.
		log.Printf("Traffic logging to %s (max %dMB, queue=%d)\n",
			trafficLog.path, trafficLog.maxSize/(1<<20), logQueueSize)
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
			eng.CleanupClientStates()
		}
	}()

	// HTTP health + metrics endpoint (with Basic Auth on mutating endpoints)
	go func() {
		h := &MgmtHandlers{}
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", h.HealthHandler)   // unauthenticated — used by Docker healthcheck
		healthMux.HandleFunc("/metrics", h.MetricsHandler) // unauthenticated — Prometheus exposition (no sensitive data)
		healthMux.HandleFunc("/stats", mgmtAuthMiddleware(h.StatsHandler))
		healthMux.HandleFunc("/reset", mgmtAuthMiddleware(h.ResetHandler))
		healthMux.HandleFunc("/categories", mgmtAuthMiddleware(h.CategoriesHandler))
		healthMux.HandleFunc("/categories/toggle", mgmtAuthMiddleware(h.CategoriesToggleHandler))
		healthMux.HandleFunc("/heuristics", mgmtAuthMiddleware(h.HeuristicsHandler))
		healthMux.HandleFunc("/heuristics/toggle", mgmtAuthMiddleware(h.HeuristicsToggleHandler))

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

// ── Management Auth Middleware ──────────────────────────────────────────────

// mgmtAuthMiddleware protects management endpoints with Basic Auth using the
// same BASIC_AUTH_USERNAME/PASSWORD credentials as the backend. Health endpoint
// is intentionally excluded (used by Docker healthcheck without credentials).
func mgmtAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	user := os.Getenv("BASIC_AUTH_USERNAME")
	pass := os.Getenv("BASIC_AUTH_PASSWORD")
	return func(w http.ResponseWriter, r *http.Request) {
		if user == "" || pass == "" {
			// No credentials configured — deny all management access
			http.Error(w, `{"error":"management auth not configured"}`, http.StatusForbidden)
			return
		}
		u, p, ok := r.BasicAuth()
		// Constant time, and both fields are always compared so the total does
		// not reveal which one failed. Plain != short-circuits on the first
		// differing byte, and this credential guards /categories/toggle — the
		// route that can switch off SQL-injection inspection — on the internal
		// bridge, where an attacker who already holds another container has a
		// low-jitter path (SECURE-SEC-02).
		okUser := subtle.ConstantTimeCompare([]byte(u), []byte(user))
		okPass := subtle.ConstantTimeCompare([]byte(p), []byte(pass))
		if !ok || okUser&okPass != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="WAF Management"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ── Management Handlers ─────────────────────────────────────────────────────

type MgmtHandlers struct{}

// MetricsHandler exposes a small set of operational counters in the
// Prometheus text exposition format. It is intentionally unauthenticated
// — only aggregate counters are emitted (no rule names, no destinations,
// no User-Agents) so it leaks nothing more than the existing /health
// endpoint already does. Wire to Prometheus with a scrape job pointed at
// http://waf:8080/metrics on the internal proxy network.
func (h *MgmtHandlers) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	totalRules := 0
	for _, cr := range engine.BlockRules() {
		totalRules += len(cr.Rules)
	}

	disabledCatCount := eng.DisabledCategoryCount()

	hcfg := eng.Heuristics()
	heuristicsEnabled := 0
	for _, on := range []bool{
		hcfg.EntropyThreshold, hcfg.BeaconingDetection,
		hcfg.PIICounter, hcfg.DestinationSharding,
		hcfg.ProtocolGhosting, hcfg.SequenceValidation,
	} {
		if on {
			heuristicsEnabled++
		}
	}

	cacheStats := eng.SafeCache().Stats()

	fmt.Fprintf(w,
		"# HELP waf_requests_total Total ICAP requests inspected.\n"+
			"# TYPE waf_requests_total counter\n"+
			"waf_requests_total %d\n"+
			"# HELP waf_blocked_total Requests blocked by the WAF.\n"+
			"# TYPE waf_blocked_total counter\n"+
			"waf_blocked_total %d\n"+
			"# HELP waf_high_entropy_total Requests flagged as high-entropy (URL or body).\n"+
			"# TYPE waf_high_entropy_total counter\n"+
			"waf_high_entropy_total %d\n"+
			"# HELP waf_requests_last_minute Approximate requests per minute (rolling reset).\n"+
			"# TYPE waf_requests_last_minute gauge\n"+
			"waf_requests_last_minute %d\n"+
			"# HELP waf_rules_total Number of regex rules loaded.\n"+
			"# TYPE waf_rules_total gauge\n"+
			"waf_rules_total %d\n"+
			"# HELP waf_categories_total Number of rule categories loaded.\n"+
			"# TYPE waf_categories_total gauge\n"+
			"waf_categories_total %d\n"+
			"# HELP waf_categories_disabled Number of rule categories currently disabled.\n"+
			"# TYPE waf_categories_disabled gauge\n"+
			"waf_categories_disabled %d\n"+
			"# HELP waf_block_threshold Score threshold at which requests are blocked.\n"+
			"# TYPE waf_block_threshold gauge\n"+
			"waf_block_threshold %d\n"+
			"# HELP waf_heuristics_enabled Number of heuristic detectors currently active.\n"+
			"# TYPE waf_heuristics_enabled gauge\n"+
			"waf_heuristics_enabled %d\n",
		stats.totalRequests.Load(),
		stats.totalBlocked.Load(),
		stats.highEntropyCount.Load(),
		stats.recentCount.Load(),
		totalRules,
		len(engine.BlockRules()),
		disabledCatCount,
		eng.BlockThreshold(),
		heuristicsEnabled,
	)

	if hits, ok := cacheStats["safe_cache_hits"]; ok {
		fmt.Fprintf(w,
			"# HELP waf_safe_cache_hits_total Cache hits on the safe-URL fast path.\n"+
				"# TYPE waf_safe_cache_hits_total counter\n"+
				"waf_safe_cache_hits_total %v\n", hits)
	}
	if size, ok := cacheStats["safe_cache_size"]; ok {
		fmt.Fprintf(w,
			"# HELP waf_safe_cache_size Number of entries currently in the safe-URL cache.\n"+
				"# TYPE waf_safe_cache_size gauge\n"+
				"waf_safe_cache_size %v\n", size)
	}

	// Observability for silent-drop paths: forensics (traffic log) and alerts
	// (backend notifications) are shed under load / when /data is read-only.
	// Without these, the failures from finding #112 are invisible to monitoring.
	trafficEnabled := 0
	if trafficLog != nil {
		trafficEnabled = 1
	}
	fmt.Fprintf(w,
		"# HELP waf_trafficlog_enabled Whether the WAF traffic feature log has a writable sink (1) or is disabled (0).\n"+
			"# TYPE waf_trafficlog_enabled gauge\n"+
			"waf_trafficlog_enabled %d\n"+
			"# HELP waf_trafficlog_dropped_total Traffic feature records dropped because the queue was full.\n"+
			"# TYPE waf_trafficlog_dropped_total counter\n"+
			"waf_trafficlog_dropped_total %d\n"+
			"# HELP waf_notify_dropped_total Backend notifications (alerts) dropped because the queue was full.\n"+
			"# TYPE waf_notify_dropped_total counter\n"+
			"waf_notify_dropped_total %d\n"+
			"# HELP waf_body_truncated_total Requests whose body exceeded the inspection limit (only a prefix was scanned).\n"+
			"# TYPE waf_body_truncated_total counter\n"+
			"waf_body_truncated_total %d\n"+
			"# HELP waf_respmod_uninspectable_total Text responses skipped because the body was compressed (coverage gap).\n"+
			"# TYPE waf_respmod_uninspectable_total counter\n"+
			"waf_respmod_uninspectable_total %d\n",
		trafficEnabled,
		trafficLogDropped.Load(),
		notifyDropped.Load(),
		bodyTruncatedCount.Load(),
		respmodUninspectable.Load(),
	)

	// REQMOD inspection latency histogram → enables p50/p95/p99 in Prometheus.
	reqmodLatency.write(w, "waf_reqmod_duration_seconds", "REQMOD request inspection latency in seconds.")
}

func (h *MgmtHandlers) HealthHandler(w http.ResponseWriter, r *http.Request) {
	total := 0
	for _, cr := range engine.BlockRules() {
		total += len(cr.Rules)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	hcfg := eng.Heuristics()
	hEnabled := 0
	for _, on := range []bool{hcfg.EntropyThreshold, hcfg.BeaconingDetection, hcfg.PIICounter, hcfg.DestinationSharding, hcfg.ProtocolGhosting, hcfg.SequenceValidation} {
		if on {
			hEnabled++
		}
	}
	fmt.Fprintf(w, `{"status":"healthy","rules":%d,"categories":%d,"threshold":%d,"heuristics":%d}`,
		total, len(engine.BlockRules()), eng.BlockThreshold(), hEnabled)
}

func (h *MgmtHandlers) StatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	snap := stats.snapshot()
	// Merge cache stats
	for k, v := range eng.SafeCache().Stats() {
		snap[k] = v
	}
	if err := json.NewEncoder(w).Encode(snap); err != nil {
		log.Printf("StatsHandler encode error: %v\n", err)
	}
}

func (h *MgmtHandlers) ResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	stats.reset()
	eng.SafeCache().Invalidate()
	log.Println("WAF stats + safe cache reset via API")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok","message":"stats reset"}`))
}

func (h *MgmtHandlers) CategoriesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	type catInfo struct {
		Name    string `json:"name"`
		Rules   int    `json:"rules"`
		Enabled bool   `json:"enabled"`
	}
	var cats []catInfo
	for _, cr := range engine.BlockRules() {
		cats = append(cats, catInfo{
			Name:    cr.Category,
			Rules:   len(cr.Rules),
			Enabled: eng.CategoryEnabled(cr.Category),
		})
	}
	if err := json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": cats}); err != nil {
		log.Printf("CategoriesHandler encode error: %v\n", err)
	}
}

func (h *MgmtHandlers) CategoriesToggleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Bound the request body — this endpoint accepts a tiny JSON object.
	// Without a limit, an attacker (after auth) could OOM the WAF by streaming
	// arbitrary bytes into json.Decoder.
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req struct {
		Category string `json:"category"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Category == "" {
		http.Error(w, `{"error":"category required"}`, http.StatusBadRequest)
		return
	}
	eng.SetCategoryEnabled(req.Category, req.Enabled)
	atomic.AddUint64(&istagEpoch, 1) // effective ruleset changed → new ISTag so Squid drops cached verdicts
	eng.SafeCache().Invalidate()     // Clear cache since rules changed
	log.Printf("Category %s: enabled=%v\n", req.Category, req.Enabled)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","category":"%s","enabled":%v}`, req.Category, req.Enabled)
}

// HeuristicsHandler returns the current on/off state of each heuristic, keyed by
// its `waf_h_*` setting key — lets the backend reconcile DB settings with the
// live engine state.
func (h *MgmtHandlers) HeuristicsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if err := json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": eng.HeuristicStates()}); err != nil {
		log.Printf("HeuristicsHandler encode error: %v\n", err)
	}
}

// HeuristicsToggleHandler flips one heuristic at runtime (mirrors
// CategoriesToggleHandler). Heuristics contribute to the anomaly score, so a
// toggle changes verdicts — bump the ISTag and drop the safe-cache so Squid and
// the WAF stop serving pre-toggle decisions.
func (h *MgmtHandlers) HeuristicsToggleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Bound the body — this endpoint accepts a tiny JSON object; without a cap an
	// authenticated caller could OOM the WAF by streaming into json.Decoder.
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req struct {
		Heuristic string `json:"heuristic"`
		Enabled   bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Heuristic == "" {
		http.Error(w, `{"error":"heuristic required"}`, http.StatusBadRequest)
		return
	}
	if !eng.SetHeuristicEnabled(req.Heuristic, req.Enabled) {
		http.Error(w, `{"error":"unknown heuristic"}`, http.StatusBadRequest)
		return
	}
	atomic.AddUint64(&istagEpoch, 1)
	eng.SafeCache().Invalidate()
	log.Printf("Heuristic %s: enabled=%v\n", req.Heuristic, req.Enabled)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","heuristic":"%s","enabled":%v}`, req.Heuristic, req.Enabled)
}
