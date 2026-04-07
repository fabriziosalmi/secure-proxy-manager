package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Behavioral Heuristic Engine — stateful, time-windowed anomaly detection.
// Each heuristic is independently toggleable via environment variables.
// ═══════════════════════════════════════════════════════════════════════════════

// HeuristicConfig holds per-heuristic settings.
type HeuristicConfig struct {
	EntropyThreshold     bool    // H1: block high-entropy egress payloads
	EntropyMax           float64 // H1: threshold (default 7.5)
	BeaconingDetection   bool    // H2: detect C2 beaconing patterns
	BeaconingWindow      int     // H2: seconds to track (default 300)
	BeaconingMinRequests int     // H2: min requests in window to evaluate (default 5)
	PIICounter           bool    // H3: count PII in response bodies
	PIIMaxPerResponse    int     // H3: max PII items before block (default 5)
	DestinationSharding  bool    // H4: detect rapid multi-destination access
	ShardingMaxDests     int     // H4: max unique destinations per IP per minute (default 50)
	HeaderMorphing       bool    // H5: detect header order/case changes
	ProtocolGhosting     bool    // H6: detect encapsulated protocols in HTTP
	SequenceValidation   bool    // H7: detect impossible request sequences
}

// HeuristicResult is returned when a heuristic fires.
type HeuristicResult struct {
	ID       string // e.g. "H1-ENTROPY"
	Category string // e.g. "HEURISTIC_ENTROPY"
	Score    int
	Detail   string
}

var heuristicCfg HeuristicConfig

func initHeuristics() {
	heuristicCfg = HeuristicConfig{
		EntropyThreshold:     envBool("WAF_H_ENTROPY", true),
		EntropyMax:           envFloat("WAF_H_ENTROPY_MAX", 7.5),
		BeaconingDetection:   envBool("WAF_H_BEACONING", true),
		BeaconingWindow:      envInt("WAF_H_BEACONING_WINDOW", 300),
		BeaconingMinRequests: envInt("WAF_H_BEACONING_MIN", 5),
		PIICounter:           envBool("WAF_H_PII", true),
		PIIMaxPerResponse:    envInt("WAF_H_PII_MAX", 5),
		DestinationSharding:  envBool("WAF_H_SHARDING", true),
		ShardingMaxDests:     envInt("WAF_H_SHARDING_MAX", 50),
		HeaderMorphing:       envBool("WAF_H_MORPHING", false), // Off by default (noisy)
		ProtocolGhosting:     envBool("WAF_H_GHOSTING", true),
		SequenceValidation:   envBool("WAF_H_SEQUENCE", false), // Off by default (needs tuning)
	}

	enabled := 0
	if heuristicCfg.EntropyThreshold {
		enabled++
	}
	if heuristicCfg.BeaconingDetection {
		enabled++
	}
	if heuristicCfg.PIICounter {
		enabled++
	}
	if heuristicCfg.DestinationSharding {
		enabled++
	}
	if heuristicCfg.HeaderMorphing {
		enabled++
	}
	if heuristicCfg.ProtocolGhosting {
		enabled++
	}
	if heuristicCfg.SequenceValidation {
		enabled++
	}
	log.Printf("Heuristic engine: %d/7 rules enabled\n", enabled)
}

// ── State tracking ──────────────────────────────────────────────────────────

type clientState struct {
	// Beaconing: track request timing per dest
	reqTimes []time.Time
	reqSizes []int

	// Destination sharding: unique dests in current window
	dests    map[string]time.Time
	destLast time.Time

	// Header morphing: last seen header fingerprint
	lastHeaderFP string

	// Sequence: last method+path
	lastMethod string
	lastPath   string
}

var (
	clientStates = make(map[string]*clientState)
	csMutex      sync.Mutex
)

func getClientState(ip string) *clientState {
	csMutex.Lock()
	defer csMutex.Unlock()
	cs, ok := clientStates[ip]
	if !ok {
		// Cap at 10K IPs to prevent unbounded memory growth
		if len(clientStates) >= 10000 {
			for k := range clientStates {
				delete(clientStates, k)
				break // evict one random entry
			}
		}
		cs = &clientState{dests: make(map[string]time.Time)}
		clientStates[ip] = cs
	}
	return cs
}

// Periodic cleanup — called from main.go
func cleanupClientStates() {
	csMutex.Lock()
	defer csMutex.Unlock()
	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, cs := range clientStates {
		if cs.destLast.Before(cutoff) && len(cs.reqTimes) == 0 {
			delete(clientStates, ip)
		}
	}
}

// ── Heuristic checks ────────────────────────────────────────────────────────

// CheckRequestHeuristics evaluates behavioral heuristics for a request.
// Returns additional score and match results.
func CheckRequestHeuristics(clientIP, method, host, path, body, rawHeaders string, bodySize int, bodyEntropy, urlEntropy float64) ([]HeuristicResult, int) {
	var results []HeuristicResult
	totalScore := 0

	cs := getClientState(clientIP)
	now := time.Now()

	// ── Snapshot & update client state under a single lock ─────────────
	// This avoids 4-5 separate lock/unlock cycles per request.
	csMutex.Lock()
	// H2: trim old beaconing entries
	var validTimes []time.Time
	var validSizes []int
	if heuristicCfg.BeaconingDetection {
		window := time.Duration(heuristicCfg.BeaconingWindow) * time.Second
		cutoff := now.Add(-window)
		for i, t := range cs.reqTimes {
			if t.After(cutoff) {
				validTimes = append(validTimes, t)
				if i < len(cs.reqSizes) {
					validSizes = append(validSizes, cs.reqSizes[i])
				}
			}
		}
		validTimes = append(validTimes, now)
		validSizes = append(validSizes, bodySize)
		// Cap ring buffer at 1000 entries to bound memory
		if len(validTimes) > 1000 {
			validTimes = validTimes[len(validTimes)-1000:]
			validSizes = validSizes[len(validSizes)-1000:]
		}
		cs.reqTimes = validTimes
		cs.reqSizes = validSizes
	}

	// H4: clean old dests, record new
	var destCount int
	if heuristicCfg.DestinationSharding {
		for d, t := range cs.dests {
			if now.Sub(t) > 60*time.Second {
				delete(cs.dests, d)
			}
		}
		cs.dests[host] = now
		cs.destLast = now
		destCount = len(cs.dests)
	}

	// H5: snapshot header FP
	var prevHeaderFP string
	if heuristicCfg.HeaderMorphing {
		prevHeaderFP = cs.lastHeaderFP
		cs.lastHeaderFP = headerFingerprint(rawHeaders)
	}

	// H7: snapshot last method/path
	var prevMethod, prevPath string
	if heuristicCfg.SequenceValidation {
		prevMethod = cs.lastMethod
		prevPath = cs.lastPath
		cs.lastMethod = method
		cs.lastPath = path
	}
	csMutex.Unlock()
	// ── End single-lock section ────────────────────────────────────────

	// ── H1: Entropy Thresholding ────────────────────────────────────────
	if heuristicCfg.EntropyThreshold {
		if bodyEntropy > heuristicCfg.EntropyMax && bodySize > 256 {
			r := HeuristicResult{
				ID:       "H1-ENTROPY",
				Category: "HEURISTIC_ENTROPY",
				Score:    10,
				Detail:   fmt.Sprintf("body entropy %.2f > %.1f (size=%d)", bodyEntropy, heuristicCfg.EntropyMax, bodySize),
			}
			results = append(results, r)
			totalScore += r.Score
		}
		if urlEntropy > heuristicCfg.EntropyMax {
			r := HeuristicResult{
				ID:       "H1-URL-ENTROPY",
				Category: "HEURISTIC_ENTROPY",
				Score:    7,
				Detail:   fmt.Sprintf("URL entropy %.2f > %.1f", urlEntropy, heuristicCfg.EntropyMax),
			}
			results = append(results, r)
			totalScore += r.Score
		}
	}

	// ── H2: Beaconing Detection ─────────────────────────────────────────
	if heuristicCfg.BeaconingDetection {
		if len(validTimes) >= heuristicCfg.BeaconingMinRequests {
			// Check for regular intervals (beaconing)
			if isBeaconing(validTimes) && isUniformSize(validSizes) {
				r := HeuristicResult{
					ID:       "H2-BEACON",
					Category: "HEURISTIC_BEACONING",
					Score:    10,
					Detail:   fmt.Sprintf("regular interval pattern detected (%d reqs in %ds)", len(validTimes), heuristicCfg.BeaconingWindow),
				}
				results = append(results, r)
				totalScore += r.Score
			}
		}
	}

	// ── H4: Destination Sharding ────────────────────────────────────────
	if heuristicCfg.DestinationSharding {
		if destCount > heuristicCfg.ShardingMaxDests {
			r := HeuristicResult{
				ID:       "H4-SHARDING",
				Category: "HEURISTIC_SHARDING",
				Score:    10,
				Detail:   fmt.Sprintf("%d unique destinations in 60s (max=%d)", destCount, heuristicCfg.ShardingMaxDests),
			}
			results = append(results, r)
			totalScore += r.Score
		}
	}

	// ── H5: Header Morphing Detection ───────────────────────────────────
	if heuristicCfg.HeaderMorphing {
		fp := headerFingerprint(rawHeaders)

		if prevHeaderFP != "" && fp != prevHeaderFP {
			r := HeuristicResult{
				ID:       "H5-MORPHING",
				Category: "HEURISTIC_MORPHING",
				Score:    4,
				Detail:   "header fingerprint changed between requests",
			}
			results = append(results, r)
			totalScore += r.Score
		}
	}

	// ── H6: Protocol Ghosting ───────────────────────────────────────────
	if heuristicCfg.ProtocolGhosting {
		if ghost := detectProtocolGhosting(body); ghost != "" {
			r := HeuristicResult{
				ID:       "H6-GHOST",
				Category: "HEURISTIC_GHOSTING",
				Score:    10,
				Detail:   fmt.Sprintf("encapsulated protocol detected: %s", ghost),
			}
			results = append(results, r)
			totalScore += r.Score
		}
	}

	// ── H7: Sequence Validation ─────────────────────────────────────────
	if heuristicCfg.SequenceValidation {
		if isInvalidSequence(prevMethod, prevPath, method, path) {
			r := HeuristicResult{
				ID:       "H7-SEQUENCE",
				Category: "HEURISTIC_SEQUENCE",
				Score:    7,
				Detail:   fmt.Sprintf("suspicious sequence: %s %s → %s %s", prevMethod, prevPath, method, path),
			}
			results = append(results, r)
			totalScore += r.Score
		}
	}

	return results, totalScore
}

// CheckResponseHeuristics checks response body for PII leaks (H3).
func CheckResponseHeuristics(body string) ([]HeuristicResult, int) {
	if !heuristicCfg.PIICounter || len(body) == 0 {
		return nil, 0
	}

	count := 0
	// Email addresses
	count += len(reEmail.FindAllString(body, -1))
	// Credit card patterns (simplified Luhn-like)
	count += len(reCreditCard.FindAllString(body, -1))
	// SSN
	count += len(reSSN.FindAllString(body, -1))

	if count > heuristicCfg.PIIMaxPerResponse {
		r := HeuristicResult{
			ID:       "H3-PII",
			Category: "HEURISTIC_PII_LEAK",
			Score:    10,
			Detail:   fmt.Sprintf("%d PII items in response (max=%d)", count, heuristicCfg.PIIMaxPerResponse),
		}
		return []HeuristicResult{r}, r.Score
	}
	return nil, 0
}

// ── Helper functions ────────────────────────────────────────────────────────

var (
	reEmail      = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	reCreditCard = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	reSSN        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

	// Protocol signatures for ghosting detection
	sshSig  = []byte("SSH-")
	smtpSig = []byte("220 ")
	ftpSig  = []byte("230 ")
)

// isBeaconing checks if request timestamps follow a regular pattern.
// Returns true if the coefficient of variation of intervals is < 0.3 (very regular).
func isBeaconing(times []time.Time) bool {
	if len(times) < 3 {
		return false
	}
	intervals := make([]float64, len(times)-1)
	var sum float64
	for i := 1; i < len(times); i++ {
		d := times[i].Sub(times[i-1]).Seconds()
		intervals[i-1] = d
		sum += d
	}
	mean := sum / float64(len(intervals))
	if mean < 1 {
		return false // Too fast to be beaconing
	}
	var variance float64
	for _, d := range intervals {
		diff := d - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))
	stddev := 0.0
	if variance > 0 {
		stddev = sqrt(variance)
	}
	cv := stddev / mean // Coefficient of variation
	return cv < 0.3     // Very regular = beaconing
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 20; i++ {
		z = (z + x/z) / 2
	}
	return z
}

// isUniformSize checks if payload sizes are suspiciously similar.
func isUniformSize(sizes []int) bool {
	if len(sizes) < 3 {
		return false
	}
	var sum float64
	for _, s := range sizes {
		sum += float64(s)
	}
	mean := sum / float64(len(sizes))
	if mean == 0 {
		return true // All zero = beaconing heartbeat
	}
	var variance float64
	for _, s := range sizes {
		diff := float64(s) - mean
		variance += diff * diff
	}
	variance /= float64(len(sizes))
	cv := sqrt(variance) / mean
	return cv < 0.2 // Very uniform sizes
}

// headerFingerprint creates a stable fingerprint from header names and order.
func headerFingerprint(rawHeaders string) string {
	lines := strings.Split(rawHeaders, "\n")
	var names []string
	for _, line := range lines {
		if idx := strings.Index(line, ":"); idx > 0 {
			names = append(names, strings.ToLower(strings.TrimSpace(line[:idx])))
		}
	}
	return strings.Join(names, "|")
}

// detectProtocolGhosting checks for non-HTTP protocols encapsulated in HTTP body.
func detectProtocolGhosting(body string) string {
	b := []byte(body)
	if len(b) < 4 {
		return ""
	}

	// SSH
	if len(b) >= 4 && string(b[:4]) == string(sshSig) {
		return "SSH"
	}
	// ELF binary
	if b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' {
		return "ELF-binary"
	}
	// PE/MZ executable
	if b[0] == 'M' && b[1] == 'Z' {
		return "PE-executable"
	}
	// SMTP
	if len(b) >= 4 && string(b[:4]) == string(smtpSig) {
		return "SMTP"
	}

	return ""
}

// isInvalidSequence detects impossible request sequences.
func isInvalidSequence(prevMethod, prevPath, curMethod, curPath string) bool {
	// POST to auth without prior GET (bot/exploit)
	if curMethod == "POST" && strings.Contains(curPath, "/login") {
		if prevMethod == "" || (prevMethod != "GET" && !strings.Contains(prevPath, "/login")) {
			return true
		}
	}
	// DELETE without prior GET (blind deletion)
	if curMethod == "DELETE" && prevMethod != "GET" && prevMethod != "" {
		return true
	}
	return false
}

// ── Env helpers ─────────────────────────────────────────────────────────────

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes"
}

func envFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}
