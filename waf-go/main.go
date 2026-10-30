package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-icap/icap"

	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/inspect"
	"secure-proxy-waf/internal/policy"
)

const (
	maxBodyInspectSize = inspect.MaxBodyInspectSize
	maxNotifyWorkers   = 8 // Bounded goroutine pool for backend notifications
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
	// notifyPending counts alerts queued or being delivered, so shutdown can
	// wait for them instead of exiting with them in the queue.
	notifyPending atomic.Int64
	// notifyFailed counts deliveries that did not reach the backend, by
	// reason. They used to be a log line each and no metric, so with a wrong
	// token every alert was lost while waf_notify_dropped_total stayed 0.
	notifyFailed = map[string]*atomic.Int64{
		"network":       new(atomic.Int64), // no answer, after the retries
		"rejected":      new(atomic.Int64), // 4xx: a credential or request problem, not retried
		"server_error":  new(atomic.Int64), // 5xx, after the retries
		"no_credential": new(atomic.Int64), // no service token (env or file) and BASIC_AUTH_* unset
	}

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
	// The engine and the observe-only set change verdicts as much as a rule
	// does.
	fmt.Fprintf(h, "E:%s\n", wafEngine)
	// The regex engines agree on the RE2 syntax but not on every corner
	// (libinjection's C original and its Go port): a switch drops cached
	// verdicts.
	fmt.Fprintf(h, "R:%s\n", engine.RegexEngine())
	for _, cat := range eng.ObserveCategories() {
		fmt.Fprintf(h, "O:%s\n", cat)
	}
	// So does the policy; a reload bumps the epoch as a toggle does.
	fmt.Fprintf(h, "P:%s\n", currentPolicy.Load().Digest())
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
// parseBlockThreshold accepts a positive integer, the only values the engine
// can act on.
func parseBlockThreshold(raw string) (int, error) {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("not an integer")
	}
	if v <= 0 {
		return 0, fmt.Errorf("must be greater than zero")
	}
	return v, nil
}

func engineConfigFromEnv() engine.Config {
	cfg := engine.Config{Heuristics: engine.HeuristicsFromEnv()}
	if envThreshold := os.Getenv("WAF_BLOCK_THRESHOLD"); envThreshold != "" {
		v, err := parseBlockThreshold(envThreshold)
		if err != nil {
			// The default stays in force, and the operator is told so. A
			// threshold set to make the WAF stricter and silently ignored is
			// worse than one that fails loudly: they would believe the change
			// took effect.
			slog.Warn("WAF_BLOCK_THRESHOLD rejected; using the built-in threshold",
				"variable", "WAF_BLOCK_THRESHOLD", "value", envThreshold, "reason", err.Error(),
				"in_use", engine.DefaultBlockThreshold)
		} else {
			cfg.BlockThreshold = v
		}
	}
	if disabled := os.Getenv("WAF_DISABLED_CATEGORIES"); disabled != "" {
		for _, cat := range strings.Split(disabled, ",") {
			if cat = strings.TrimSpace(cat); cat != "" {
				cfg.DisabledCategories = append(cfg.DisabledCategories, cat)
			}
		}
		slog.Info("WAF categories disabled at start-up", "categories", cfg.DisabledCategories)
	}
	return cfg
}

func init() {
	setupLogging()
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WAF_FAIL_OPEN"))) {
	case "1", "true", "yes", "on":
		wafFailOpen = true
		slog.Warn("WAF_FAIL_OPEN=1: REQMOD handler panics will ALLOW traffic (availability over security)")
	}

	// Rules first: the pre-filter gates the custom rules too (#110), and the
	// ISTag digest must cover the set actually loaded.
	engine.LoadCustomRules(engine.DefaultCustomRulesPath)
	if err := engine.ValidateRegexEngine(); err != nil {
		slog.Error("WAF not started", "error", err.Error())
		os.Exit(1)
	}
	engine.BuildPrefilter()
	name, c, observe, err := selectEngine(os.Getenv)
	if err != nil {
		slog.Error("WAF not started", "error", err.Error())
		os.Exit(1)
	}
	wafEngine, crsEng = name, c
	cfg := engineConfigFromEnv()
	cfg.ObserveCategories = observe
	warnUnknownCategories("WAF_OBSERVE_CATEGORIES", observe)
	eng = engine.New(cfg)
	if err := loadPolicyAtStart(); err != nil {
		slog.Error("WAF not started", "error", err.Error())
		os.Exit(1)
	}
	initISTag()

	total := 0
	for _, cr := range engine.BlockRules() {
		total += len(cr.Rules)
	}
	log.Printf("WAF engine initialized: %d regex rules + 7 heuristic checks across %d categories (block threshold: %d)\n",
		total, len(engine.BlockRules()), eng.BlockThreshold())
	slog.Info("WAF engine selected", "engine", wafEngine, "regex_engine", engine.RegexEngine(), "crs", crsEng != nil, "observe_categories", eng.ObserveCategories())
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
	log.Printf("no backend alert credential: INTERNAL_ALERT_TOKEN is unset and %s is missing; mount the "+
		"service-token volume read-only as the shipped compose files do, or set INTERNAL_ALERT_TOKEN "+
		"(openssl rand -hex 32) on both the waf and backend services; alerts are being dropped\n", serviceTokenFile())
}

// notifyAttempts bounds the deliveries of one alert; notifyRetryDelay is the
// wait before retry n (a variable so tests need not sleep).
const notifyAttempts = 3

var notifyRetryDelay = func(attempt int) time.Duration { return time.Duration(250<<attempt) * time.Millisecond }

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
	alertToken := serviceToken()
	authUser := os.Getenv("BASIC_AUTH_USERNAME")
	authPass := os.Getenv("BASIC_AUTH_PASSWORD")
	if alertToken == "" && (authUser == "" || authPass == "") {
		notifyFailed["no_credential"].Add(1)
		warnNoAlertCredential()
		return
	}

	payload, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal alert data: %v\n", err)
		return
	}
	eventID := ""
	if d, ok := data["details"].(map[string]interface{}); ok {
		eventID, _ = d["event_id"].(string)
	}

	// A 4xx is the backend refusing this credential or this payload, which a
	// retry cannot fix; a network error or a 5xx may pass on the next try.
	for attempt := 0; attempt < notifyAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(notifyRetryDelay(attempt - 1))
		}
		req, err := http.NewRequest("POST", backendURL+"/api/internal/alert", bytes.NewReader(payload))
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

		resp, err := notifyClient.Do(req)
		if err != nil {
			if attempt == notifyAttempts-1 {
				notifyFailed["network"].Add(1)
				slog.Warn("alert not delivered to the backend", "event_id", eventID, "reason", "network", "attempts", notifyAttempts, "error", err.Error())
			}
			continue
		}
		resp.Body.Close()
		switch {
		case resp.StatusCode < 400:
			return
		case resp.StatusCode < 500:
			notifyFailed["rejected"].Add(1)
			slog.Warn("alert rejected by the backend: check INTERNAL_ALERT_TOKEN on the waf and backend services",
				"event_id", eventID, "status", resp.StatusCode)
			return
		case attempt == notifyAttempts-1:
			notifyFailed["server_error"].Add(1)
			slog.Warn("alert not delivered to the backend", "event_id", eventID, "reason", "server_error",
				"status", resp.StatusCode, "attempts", notifyAttempts)
		}
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
		slog.Error("PANIC in ICAP handler", "method", method, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
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

// inspection is one REQMOD pass: the request verdict (inspect.Inspection,
// shared with the wafeval harness) plus what only the ICAP handler needs,
// the event ID, the start time and the safe-URL cache addressing.
type inspection struct {
	*inspect.Inspection

	eventID   string
	startTime time.Time

	// Safe-URL cache addressing, computed once up front and reused at the end.
	cacheable bool
	cacheKey  string
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
		Inspection: &inspect.Inspection{
			Eng:      eng,
			CRSEng:   crsEng,
			Policy:   currentPolicy.Load(),
			RawURL:   req.Request.URL.String(),
			ClientIP: clientIPFrom(req),
		},
		eventID:   nextEventID(startTime),
		startTime: startTime,
	}

	// Skip WAF inspection for LAN destinations (proxy UI, backend, local
	// services). These are legitimate internal traffic, not SSRF attempts.
	if engine.IsLANHost(req.Request.Host) {
		passThrough(w, req)
		return
	}

	// ── Safe URL Cache: skip the URL scan for known-clean URLs ──────────
	// Scoped by method, so a clean GET never vouches for a POST. A hit skips
	// only the URL-dependent work. It used to return 204 here, before anything
	// else ran, so after one clean GET the same URL with a payload in a
	// header or a GET body was not inspected at all, and the request never
	// reached the heuristics or the traffic log.
	in.cacheable = req.Request.Method == http.MethodGet || req.Request.Method == http.MethodHead
	in.cacheKey = req.Request.Method + "\x00" + in.RawURL
	in.URLCached = in.cacheable && eng.SafeCache().IsSafe(in.cacheKey)

	in.Scan(req.Request)
	in.logScanFindings(req.Request.Host)

	feature := in.feature(req.Request)
	in.Heuristics(req.Request, feature.BodyEntropy, feature.URLEntropy)
	in.RunCRS(req.Request)

	ruleIDs, categories := in.Verdict()
	feature.WAFScore = in.Score
	if in.CRS != nil {
		feature.CRSScore = in.CRS.Score
	}
	feature.WAFRules = ruleIDs
	feature.Excepted = in.Excepted
	feature.Action = "allow"
	if in.Blocked() {
		feature.Action = "block"
	}
	// The whole WAF observes: the request passes, and the record says it
	// would not have.
	feature.WouldBlock = in.WouldBlock() && !in.Blocked()
	if feature.WouldBlock {
		wouldBlock.Add(1)
	}
	if n := len(in.Excepted); n > 0 {
		exceptionHits.Add(int64(n))
	}

	// Non-blocking: Write() enqueues to bounded channel, record() uses atomics
	trafficLog.Write(feature)
	stats.record(feature, in.Blocked(), categories)

	// Log all matches for observability, even if below threshold
	if len(ruleIDs) > 0 && !in.Blocked() {
		slog.Info("WAF OBSERVE", "event_id", in.eventID, "client_ip", in.ClientIP,
			"score", in.Score, "threshold", eng.BlockThreshold(), "would_block", feature.WouldBlock,
			"rules", ruleIDs, "url", truncate(in.RawURL, 200))
	}

	if in.Blocked() {
		block(w, in, ruleIDs, categories)
		return
	}

	// Cache the URL only when the whole request scored zero. A URL below the
	// threshold is unproven, not clean: its partial score has to be there to
	// corroborate whatever a later request adds.
	if in.cacheable && !in.URLCached && in.Score == 0 && in.BodySize == 0 {
		eng.SafeCache().MarkSafe(in.cacheKey)
	}
	passThrough(w, req)
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

// logScanFindings records what Scan found that has its own log line or
// counter: an over-limit body, a DGA-looking host, a typosquat.
func (in *inspection) logScanFindings(host string) {
	if in.BodyTruncated {
		bodyTruncatedCount.Add(1)
	}
	if in.DGA != nil {
		// %q quotes + escapes control bytes so an attacker-controlled Host
		// header (newline, tab, ANSI escapes) cannot forge log entries.
		slog.Info("WAF ML-DGA", "event_id", in.eventID, "client_ip", in.ClientIP, "domain", host, "dga_score", in.DGA.Score)
	}
	if in.Typo != nil {
		slog.Info("WAF ML-TYPO", "event_id", in.eventID, "client_ip", in.ClientIP, "domain", host,
			"target", in.Typo.Target, "technique", in.Typo.Technique, "distance", in.Typo.Distance)
	}
}

// feature builds the traffic record for this request. The score and action it
// carries are provisional: the heuristics run against its entropy fields, so
// they are recomputed by the caller once those have contributed.
func (in *inspection) feature(r *http.Request) TrafficFeature {
	ruleIDs, _ := inspect.Summarize(in.Matches)
	action := "allow"
	if in.Blocked() {
		action = "block"
	}
	return TrafficFeature{
		EventID:         in.eventID,
		Timestamp:       in.startTime.UTC().Format(time.RFC3339),
		ClientIP:        in.ClientIP,
		Method:          r.Method,
		Host:            r.Host,
		Path:            r.URL.Path,
		URLLength:       len(in.RawURL),
		URLEntropy:      engine.ShannonEntropy(in.RawURL),
		QueryParamCount: len(r.URL.Query()),
		BodySize:        in.BodySize,
		BodyEntropy:     engine.ShannonEntropy(in.BodyStr),
		ContentType:     r.Header.Get("Content-Type"),
		HeaderCount:     in.HeaderCount,
		UserAgent:       r.Header.Get("User-Agent"),
		IsTLS:           r.URL.Scheme == "https",
		DestPort:        r.URL.Port(),
		WAFScore:        in.Score,
		WAFRules:        ruleIDs,
		Action:          action,
		LatencyUS:       time.Since(in.startTime).Microseconds(),
	}
}

// block logs the decision, applies the tar-pit to repeat offenders, notifies
// the backend and writes the block page.
func block(w icap.ResponseWriter, in *inspection, ruleIDs, categories []string) {
	source := "URL"
	if in.BodyStr != "" {
		source = "URL+BODY"
	}
	primaryCategory := "UNKNOWN"
	if len(categories) > 0 {
		primaryCategory = categories[0]
	}

	// The score is the one that crossed its threshold: the spm score, or
	// CRS's inbound anomaly score when CRS blocked alone.
	score, by := in.Score, "spm"
	if !eng.Blocked(in.Score) && in.CRS != nil {
		score, by = in.CRS.Score, "crs"
	}
	slog.Info("WAF BLOCKED", "event_id", in.eventID, "client_ip", in.ClientIP,
		"score", in.Score, "threshold", eng.BlockThreshold(), "blocked_by", by, "crs_score", crsScore(in.Inspection),
		"categories", categories, "rules", ruleIDs, "source", source, "url", truncate(in.RawURL, 200))

	tarPit(in.ClientIP)
	notifyBlock(blockAlert{EventID: in.eventID, ClientIP: in.ClientIP, RawURL: in.RawURL, Source: source,
		Score: score, Categories: categories, Rules: ruleIDs, ScoringRules: in.ScoringRules(), BlockedBy: by,
		CRSScore: crsScore(in.Inspection), CRSTargets: crsTargets(in.Inspection)})
	sendBlockResponse(w, primaryCategory, score, in.eventID)
}

// crsTargets are the variables CRS's scoring rules matched on this block, as
// a policy exception names them; observed rules are left out.
func crsTargets(in *inspect.Inspection) []map[string]string {
	if in.CRS == nil {
		return nil
	}
	scoring := map[string]bool{}
	for _, id := range in.CRS.Rules {
		scoring[id] = true
	}
	var out []map[string]string
	for _, t := range in.CRS.Targets {
		if id := strconv.Itoa(t.Rule); scoring[id] {
			out = append(out, map[string]string{"rule": "CRS-" + id, "target": t.Name()})
		}
	}
	return out
}

// crsScore is CRS's inbound anomaly score, 0 when CRS did not run.
func crsScore(in *inspect.Inspection) int {
	if in.CRS == nil {
		return 0
	}
	return in.CRS.Score
}

// blockAlert is what the backend is told about a block. Host and path are
// the request's, as a policy exception scopes them; ScoringRules are the
// rules that added to a score, the ones an exception can take off (Rules
// also names the observed ones); BlockedBy says which
// half crossed its threshold (spm or crs); CRSTargets name what each
// scoring CRS rule matched, so the block can become an exception for one
// argument.
type blockAlert struct {
	EventID, ClientIP, RawURL, Source string
	Score                             int
	Categories, Rules, ScoringRules   []string
	BlockedBy                         string
	CRSScore                          int
	CRSTargets                        []map[string]string
}

// notifyBlock queues the backend notification for a block, from a request or
// from a response. It never waits: when the backend cannot keep up the alert
// is dropped and counted (circuit breaker).
func notifyBlock(a blockAlert) {
	primaryCategory := "UNKNOWN"
	if len(a.Categories) > 0 {
		primaryCategory = a.Categories[0]
	}
	host, path := "", ""
	if u, err := url.Parse(a.RawURL); err == nil {
		host, path = policy.RequestHost(u.Host), truncate(u.Path, 500)
	}
	if a.CRSTargets == nil {
		a.CRSTargets = []map[string]string{}
	}
	if a.ScoringRules == nil {
		a.ScoringRules = a.Rules
	}
	alertData := map[string]interface{}{
		"event_type": "waf_block",
		"message":    fmt.Sprintf("WAF blocked %s: score %d, categories: %s", a.Source, a.Score, strings.Join(a.Categories, ", ")),
		"details": map[string]interface{}{
			"event_id":      a.EventID,
			"category":      primaryCategory,
			"categories":    a.Categories,
			"rules":         a.Rules,
			"scoring_rules": a.ScoringRules,
			"score":         a.Score,
			"threshold":     eng.BlockThreshold(),
			"url":           truncate(a.RawURL, 500),
			"host":          host,
			"path":          path,
			"client_ip":     a.ClientIP,
			"source":        a.Source,
			"blocked_by":    a.BlockedBy,
			"crs_score":     a.CRSScore,
			"crs_targets":   a.CRSTargets,
		},
		"level": "error",
	}
	notifyPending.Add(1)
	select {
	case notifyChan <- alertData:
	default:
		notifyPending.Add(-1)
		notifyDropped.Add(1)
	}
}

// notifyWorker delivers queued alerts until stop is closed (nil: forever).
func notifyWorker(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case data := <-notifyChan:
			notifyBackend(data)
			notifyPending.Add(-1)
		}
	}
}

// drainPendingAlerts waits until every queued alert has been delivered or has
// failed, or until timeout; it reports whether the queue emptied.
func drainPendingAlerts(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for notifyPending.Load() > 0 {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

// blockResponse blocks a response in RESPMOD. It used to write the block page
// with no event ID, so a blocked download or a leaked secret reached neither
// the backend's notifications nor, through X-WAF-Event-Id, the access log row
// of the request: only the 403 and the reason "waf" were left to see.
func blockResponse(w icap.ResponseWriter, req *icap.Request, category string, score int, ruleIDs []string, logAttrs ...any) {
	eventID := nextEventID(time.Now())
	clientIP := clientIPFrom(req)
	rawURL := ""
	if req.Request != nil && req.Request.URL != nil {
		rawURL = req.Request.URL.String()
	}
	slog.Info("RESPMOD BLOCKED", append([]any{"event_id", eventID, "client_ip", clientIP,
		"score", score, "category", category, "rules", ruleIDs, "url", truncate(rawURL, 200)}, logAttrs...)...)
	notifyBlock(blockAlert{EventID: eventID, ClientIP: clientIP, RawURL: rawURL, Source: "RESPONSE",
		Score: score, Categories: []string{category}, Rules: ruleIDs, BlockedBy: "spm"})
	sendBlockResponse(w, category, score, eventID)
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
		slog.Info("TAR-PITTING", "client_ip", clientIP, "blocks_last_minute", blockCount, "delay", tarPitDelay.String())
		time.Sleep(tarPitDelay)
		slog.Info("TAR-PIT released", "client_ip", clientIP)
	}
}

func handleRespmod(w icap.ResponseWriter, req *icap.Request) {
	w.Header().Set("ISTag", currentISTag())
	if req.Response == nil {
		w.WriteHeader(204, nil, false)
		return
	}
	v := inspect.EvaluateResponse(eng, req.Response)
	switch {
	case v.Uninspectable:
		respmodUninspectable.Add(1)
		passThrough(w, req)
	case v.Blocked:
		blockResponse(w, req, v.Category, v.Score, v.Rules, "content_type", req.Response.Header.Get("Content-Type"))
	default:
		passThrough(w, req)
	}
}

// allowsNoContent reports whether the ICAP client accepts a 204 for this
// transaction: only when it sent "Allow: 204" (RFC 3507, 4.6).
func allowsNoContent(req *icap.Request) bool {
	for _, v := range req.Header.Values("Allow") {
		for _, tok := range strings.Split(v, ",") {
			if strings.TrimSpace(tok) == "204" {
				return true
			}
		}
	}
	return false
}

// passThrough answers "no modification". With "Allow: 204" that is a 204.
// Squid leaves 204 out when it cannot keep a copy of the body, which it does
// for 64 KiB or more; a 204 then is a protocol error that Squid turns into a
// 500 for the client, and eleven of them suspend the ICAP service, which with
// REQMOD fail-closed refused every client for three minutes. Without the
// header the original message goes back unchanged in a 200.
func passThrough(w icap.ResponseWriter, req *icap.Request) {
	if allowsNoContent(req) {
		w.WriteHeader(204, nil, false)
		return
	}
	var msg interface{}
	var body io.Reader
	switch {
	case req.Method == "RESPMOD" && req.Response != nil:
		msg, body = req.Response, req.Response.Body
	case req.Request != nil:
		msg, body = req.Request, req.Request.Body
	default:
		w.WriteHeader(204, nil, false)
		return
	}
	hasBody := body != nil && body != http.NoBody
	w.WriteHeader(200, msg, hasBody)
	if hasBody {
		if _, err := io.Copy(w, body); err != nil {
			slog.Warn("ICAP pass-through: body copy failed", "method", req.Method, "error", err.Error())
		}
	}
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
	// An ICAP response header, not an HTTP one: Squid logs it from the ICAP
	// reply (%{X-SPM-Reason}adapt::<last_h in the spm logformat), which only
	// this service writes, so the backend can tell a WAF block from a Squid
	// deny (both are a 403) and an upstream server cannot claim to be the WAF.
	w.Header().Set("X-SPM-Reason", "waf")
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
		go notifyWorker(nil)
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

	// The policy file is re-read when it changes, without a restart.
	go watchPolicy(nil)

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
		healthMux.HandleFunc("/policy", mgmtAuthMiddleware(h.PolicyHandler))
		healthMux.HandleFunc("/policy/reload", mgmtAuthMiddleware(h.PolicyReloadHandler))
		healthMux.HandleFunc("/policy/validate", mgmtAuthMiddleware(h.PolicyValidateHandler))

		log.Printf("Starting health endpoint on :8080\n")
		// Bounded like the backend's server: without timeouts a client that
		// opens connections and sends nothing holds them, and this listener
		// also answers the Docker healthcheck.
		mgmtSrv := &http.Server{
			Addr:              ":8080",
			Handler:           healthMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		if err := mgmtSrv.ListenAndServe(); err != nil {
			log.Printf("Health endpoint error: %v\n", err)
		}
	}()

	// On SIGTERM (docker stop, an upgrade) deliver the queued block alerts and
	// flush the traffic log before exiting. The process used to have no signal
	// handler, so both were lost on every restart. In-flight ICAP transactions
	// are still cut: the ICAP library has no graceful shutdown (#143).
	sigCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stopSignals()
	go func() {
		<-sigCtx.Done()
		pending := notifyPending.Load()
		drained := drainPendingAlerts(5 * time.Second)
		trafficLog.Close()
		slog.Info("WAF shutting down", "alerts_pending_at_signal", pending, "alerts_delivered", drained)
		os.Exit(0)
	}()

	port := 1344
	log.Printf("Starting Go ICAP WAF server on port %d...\n", port)
	err := icap.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		log.Fatalf("Error starting server: %v\n", err)
	}
}

// ── Service token ───────────────────────────────────────────────────────────

// defaultServiceTokenFile matches the backend's config.DefaultServiceTokenFile:
// one volume mounted read-write in the backend and read-only here.
const defaultServiceTokenFile = "/var/lib/spm-service-token/alert_token"

// serviceToken is the credential shared with the backend: INTERNAL_ALERT_TOKEN
// when it is set, otherwise the token the backend generated into the shared
// volume (SPM_SERVICE_TOKEN_FILE overrides the path). It is read on each use,
// which is a few times a minute, so a token the backend writes or replaces
// after this process started is picked up without a restart.
func serviceToken() string {
	if t := strings.TrimSpace(os.Getenv("INTERNAL_ALERT_TOKEN")); t != "" {
		return t
	}
	data, err := os.ReadFile(serviceTokenFile()) // #nosec G304 -- fixed path or the operator's SPM_SERVICE_TOKEN_FILE
	if err != nil {
		return ""
	}
	if t := strings.TrimSpace(string(data)); len(t) == 64 {
		return t
	}
	return ""
}

// serviceTokenFile is where the backend writes the shared token.
func serviceTokenFile() string {
	if p := os.Getenv("SPM_SERVICE_TOKEN_FILE"); p != "" {
		return p
	}
	return defaultServiceTokenFile
}

// ── Management Auth Middleware ──────────────────────────────────────────────

// mgmtAuthMiddleware protects the management endpoints. The credential is
// INTERNAL_ALERT_TOKEN, the backend/WAF service token the shipped compose gives
// both services, presented as "Authorization: Bearer". Basic auth against
// BASIC_AUTH_USERNAME/PASSWORD is still accepted when those are set, for
// deployments that pass the admin credential to the WAF themselves.
//
// It used to read BASIC_AUTH_* only. The compose stopped passing them to the
// WAF (SECURE-AUTH-02), so on every real deployment this answered 403 "not
// configured" to the backend, silently. /health and /metrics stay open (Docker
// healthcheck, Prometheus).
func mgmtAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	user := os.Getenv("BASIC_AUTH_USERNAME")
	pass := os.Getenv("BASIC_AUTH_PASSWORD")
	return func(w http.ResponseWriter, r *http.Request) {
		// Per request: the backend may write the shared token after the WAF
		// has started.
		token := serviceToken()
		if token == "" && (user == "" || pass == "") {
			// No credentials configured — deny all management access
			http.Error(w,
				`{"error":"management auth not configured: mount the service-token volume or set INTERNAL_ALERT_TOKEN on the waf and backend services"}`,
				http.StatusForbidden)
			return
		}
		if token != "" {
			if bearer, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); found &&
				subtle.ConstantTimeCompare([]byte(bearer), []byte(token)) == 1 {
				next(w, r)
				return
			}
		}
		if user == "" || pass == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="WAF Management"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
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

	fmt.Fprintf(w, "# HELP waf_build_info Source revision this WAF binary was built from.\n# TYPE waf_build_info gauge\nwaf_build_info{commit=%q} 1\n", GitCommit)
	fmt.Fprintf(w, "# HELP waf_engine_info Request engine in force (WAF_ENGINE) and the regex engine its rules run on (WAF_REGEX_ENGINE).\n# TYPE waf_engine_info gauge\nwaf_engine_info{engine=%q,regex=%q} 1\n", wafEngine, engine.RegexEngine())

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

	// The keys are SafeURLCache.Stats()'s. These two read "safe_cache_hits" and
	// "safe_cache_size", which Stats() never returned, so neither metric was
	// ever written.
	if hits, ok := cacheStats["cache_hits"]; ok {
		fmt.Fprintf(w,
			"# HELP waf_safe_cache_hits_total Cache hits on the safe-URL fast path.\n"+
				"# TYPE waf_safe_cache_hits_total counter\n"+
				"waf_safe_cache_hits_total %v\n", hits)
	}
	if size, ok := cacheStats["cache_size"]; ok {
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
	// 1 while records reach a file; 0 when the logger exists but its sink is
	// down (disk full, directory removed). Distinct from enabled, which only
	// says a sink was found at start-up.
	trafficWritable := 0
	if trafficLog.Writable() {
		trafficWritable = 1
	}
	fmt.Fprintf(w,
		"# HELP waf_trafficlog_enabled Whether the WAF traffic feature log has a writable sink (1) or is disabled (0).\n"+
			"# TYPE waf_trafficlog_enabled gauge\n"+
			"waf_trafficlog_enabled %d\n"+
			"# HELP waf_trafficlog_dropped_total Traffic feature records dropped because the queue was full.\n"+
			"# TYPE waf_trafficlog_dropped_total counter\n"+
			"waf_trafficlog_dropped_total %d\n"+
			"# HELP waf_trafficlog_writable Whether records are currently reaching a file (1) or the sink is down (0).\n"+
			"# TYPE waf_trafficlog_writable gauge\n"+
			"waf_trafficlog_writable %d\n"+
			"# HELP waf_trafficlog_sink_dropped_total Traffic feature records dropped because no log file could be opened.\n"+
			"# TYPE waf_trafficlog_sink_dropped_total counter\n"+
			"waf_trafficlog_sink_dropped_total %d\n"+
			"# HELP waf_notify_dropped_total Backend notifications (alerts) dropped because the queue was full.\n"+
			"# TYPE waf_notify_dropped_total counter\n"+
			"waf_notify_dropped_total %d\n"+
			"# HELP waf_notify_failed_total Backend notifications (alerts) that did not reach the backend, by reason.\n"+
			"# TYPE waf_notify_failed_total counter\n"+
			"waf_notify_failed_total{reason=\"network\"} %d\n"+
			"waf_notify_failed_total{reason=\"rejected\"} %d\n"+
			"waf_notify_failed_total{reason=\"server_error\"} %d\n"+
			"waf_notify_failed_total{reason=\"no_credential\"} %d\n"+
			"# HELP waf_body_truncated_total Requests whose body exceeded the inspection limit (only a prefix was scanned).\n"+
			"# TYPE waf_body_truncated_total counter\n"+
			"waf_body_truncated_total %d\n"+
			"# HELP waf_respmod_uninspectable_total Text responses skipped because the body was compressed (coverage gap).\n"+
			"# TYPE waf_respmod_uninspectable_total counter\n"+
			"waf_respmod_uninspectable_total %d\n",
		trafficEnabled,
		trafficLogDropped.Load(),
		trafficWritable,
		trafficLogSinkDropped.Load(),
		notifyDropped.Load(),
		notifyFailed["network"].Load(),
		notifyFailed["rejected"].Load(),
		notifyFailed["server_error"].Load(),
		notifyFailed["no_credential"].Load(),
		bodyTruncatedCount.Load(),
		respmodUninspectable.Load(),
	)

	writePolicyMetrics(w)

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
	// The policy's mode and size, and whether its last reload failed; the
	// reason, which names the operator's hosts, is behind GET /policy.
	pol := currentPolicy.Load()
	policyMu.Lock()
	policyFailed := policyLastError != ""
	policyMu.Unlock()
	fmt.Fprintf(w, `{"status":"healthy","commit":%q,"engine":%q,"regex_engine":%q,"rules":%d,"categories":%d,"threshold":%d,"heuristics":%d,`+
		`"policy":{"mode":%q,"exceptions":%d,"reload_failed":%t}}`,
		GitCommit, wafEngine, engine.RegexEngine(), total, len(engine.BlockRules()), eng.BlockThreshold(), hEnabled,
		pol.Mode(), pol.Exceptions(), policyFailed)
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
		// Observe: the category matches and is logged, never scored.
		Observe bool `json:"observe"`
	}
	var cats []catInfo
	for _, cr := range engine.BlockRules() {
		cats = append(cats, catInfo{
			Name:    cr.Category,
			Rules:   len(cr.Rules),
			Enabled: eng.CategoryEnabled(cr.Category),
			Observe: eng.Observed(cr.Category),
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
	slog.Info("WAF category toggled", "category", req.Category, "enabled", req.Enabled)
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
	slog.Info("WAF heuristic toggled", "heuristic", req.Heuristic, "enabled", req.Enabled)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","heuristic":"%s","enabled":%v}`, req.Heuristic, req.Enabled)
}
