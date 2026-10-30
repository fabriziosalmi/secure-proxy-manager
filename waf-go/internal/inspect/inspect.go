// Package inspect is the request half of the WAF verdict: the signature scan
// of the URL, the inspected headers and the body, the domain reputation signals
// and the stateful heuristics, accumulated into one score.
//
// It has no side effects beyond the engine's own state (the heuristics' per
// client windows): no logging, no counters, no traffic log, no cache writes.
// The ICAP handler in package main owns those. The split exists so that the
// same code path can be driven by something other than ICAP, such as the
// wafeval measurement harness, and measured as it runs in production.
package inspect

import (
	"bytes"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	"secure-proxy-waf/internal/crs"
	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/policy"
)

// MaxBodyInspectSize is how much of a request or response body is inspected.
const MaxBodyInspectSize = 1 << 20 // 1 MB

// headersNotInspected are the request headers the signature scan leaves
// out: framing and hop-by-hop headers, which Go and Squid parse before any
// rule could matter, and credentials, so that a match excerpt never copies a
// token into the logs. Every other header is scanned. With a fixed list of
// six (User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host, Accept,
// Cookie), a payload in any other header was never looked at: 0 of 300 in
// wafeval's custom-header mutations.
var headersNotInspected = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Te": true,
	"Trailer": true, "Connection": true, "Keep-Alive": true, "Proxy-Connection": true,
	"Upgrade": true, "Authorization": true, "Proxy-Authorization": true,
}

// InspectedHeaderText is the text of every inspected request header, in
// name order so a scan is deterministic, and how many headers it holds.
func InspectedHeaderText(h http.Header) (string, int) {
	names := make([]string, 0, len(h))
	for name := range h {
		if !headersNotInspected[http.CanonicalHeaderKey(name)] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var b strings.Builder
	n := 0
	for _, name := range names {
		for _, v := range h[name] {
			if v != "" {
				b.WriteString(" ")
				b.WriteString(v)
				n++
			}
		}
	}
	return b.String(), n
}

// textPlainObserveOnly are the request-rule categories that only observe on
// a text/plain body: in pasted text, <script>, a ".env",
// an "ftp://", a 192.168 address or `a" #` are words, not a request. The
// categories that mean something as text (exfiltration, mining, webshell
// and C2, ransomware, ...) still score.
var textPlainObserveOnly = map[string]bool{
	"XSS_ATTACKS": true, "COMMAND_INJECTION": true, "SQL_INJECTION": true, "SSRF": true,
	"DIRECTORY_TRAVERSAL": true, "PATH_MANIPULATION": true, "SENSITIVE_FILES": true,
}

var (
	textPlainScoredOnce sync.Once
	textPlainScoredSet  map[string]bool
)

// textPlainScored is every request-rule category but textPlainObserveOnly.
// Computed once: the rule set, custom rules included, is fixed at start-up.
func textPlainScored() map[string]bool {
	textPlainScoredOnce.Do(func() {
		textPlainScoredSet = map[string]bool{}
		for _, cr := range engine.BlockRules() {
			if !textPlainObserveOnly[cr.Category] {
				textPlainScoredSet[cr.Category] = true
			}
		}
	})
	return textPlainScoredSet
}

// isTextPlain reports whether a Content-Type is text/plain, parameters aside.
func isTextPlain(ct string) bool {
	mt, _, _ := strings.Cut(ct, ";")
	return strings.EqualFold(strings.TrimSpace(mt), "text/plain")
}

// Inspection accumulates everything one REQMOD pass learns about a request.
// It exists so the stages below can be separate functions that still share the
// running score: handleReqmod used to be a single 226-line body at cyclomatic
// complexity 48, on the hottest path in the product, with no seam a test could
// reach (SECURE-QUAL-02).
type Inspection struct {
	Eng *engine.Engine
	// CRSEng is the OWASP Core Rule Set half of the hybrid engine; nil runs
	// the spm engine alone (WAF_ENGINE=legacy).
	CRSEng *crs.Engine
	// Explain asks CRS for what each of its rules matched (wafeval).
	Explain bool
	// Policy is the operator's log-only settings and exceptions; nil is none.
	Policy *policy.Policy

	RawURL   string
	ClientIP string

	// Accumulated signals. Score is the sum of every match's Score, and the
	// block decision is Blocked(Score), checked once, at the end.
	Matches []engine.MatchResult
	Score   int

	// Body inspection results, needed later for the traffic feature and to
	// decide whether a clean verdict may be cached.
	BodyStr       string
	BodySize      int
	BodyTruncated bool

	HeaderCount int

	// URLCached means this method+URL scored zero recently, so the URL scan
	// and the domain reputation check (which depend on nothing else) are
	// skipped. Headers, body and heuristics still run: the cache vouches for
	// a URL, never for a request.
	URLCached bool

	// Domain reputation findings, for the caller to log. Nil when the check
	// did not run or found nothing.
	DGA  *engine.DGAResult
	Typo *engine.TyposquatResult

	// CRS is the Core Rule Set's verdict; nil when it did not run.
	CRS *crs.Result

	// Excepted are the rules the policy took off this request that matched:
	// spm IDs and CRS-<id> (a CRS rule taken off does not run, so only the
	// spm ones can be seen matching).
	Excepted []string

	// bodyRaw is the body as scanBody read it, before normalization, for
	// CRS; bodyRead says scanBody read it.
	bodyRaw  []byte
	bodyRead bool

	applied *policy.Applied
}

// WouldBlock is the verdict: the spm score at the threshold, or a CRS block.
// Every spm stage adds to Score; CRS runs last and decides on its own.
func (in *Inspection) WouldBlock() bool {
	return in.Eng.Blocked(in.Score) || in.CRS != nil && in.CRS.Blocked
}

// Blocked is the verdict acted on: WouldBlock, unless the policy has the
// whole WAF log only.
func (in *Inspection) Blocked() bool {
	return in.WouldBlock() && (in.Policy == nil || !in.Policy.Observe())
}

// filter is the policy as it applies to this request, nil with no policy or
// one that changes no single rule.
func (in *Inspection) filter(r *http.Request) *policy.Applied {
	if in.Policy == nil || in.Policy.Inert() {
		return nil
	}
	if in.applied == nil {
		in.applied = in.Policy.For(r.Host, r.URL.Path)
	}
	return in.applied
}

// ruleFilter is filter as the engine takes it: a nil *policy.Applied must be
// a nil interface, not an interface holding nil.
func (in *Inspection) ruleFilter(r *http.Request) engine.RuleFilter {
	if a := in.filter(r); a != nil {
		return a
	}
	return nil
}

// match runs the rule set over input under the policy and records the result.
func (in *Inspection) match(r *http.Request, input string, only map[string]bool) int {
	matches, skipped, score := in.Eng.MatchRulesFiltered(input, only, in.ruleFilter(r))
	in.Matches = append(in.Matches, matches...)
	in.Excepted = append(in.Excepted, skipped...)
	in.Score += score
	return score
}

// RunCRS is the CRS half of the hybrid engine, run after the spm stages.
// It does not run without a CRS engine (legacy), on a CONNECT (CRS has
// nothing to say about a host name, and costs five times as much there),
// or when the spm stages have already blocked.
func (in *Inspection) RunCRS(r *http.Request) {
	if in.CRSEng == nil || r.Method == http.MethodConnect || in.WouldBlock() {
		return
	}
	body := in.bodyRaw
	if !in.bodyRead {
		body = peekBody(r)
	}
	var pol crs.Policy
	if a := in.filter(r); a != nil {
		pol = a.CRS()
	}
	res := in.CRSEng.InspectWith(r, body, in.ClientIP, in.Explain, pol)
	in.CRS = &res
}

// peekBody reads up to crs.BodyLimit bytes of a body the spm scan did not
// read (a content type it skips) and puts them back in front of the rest.
func peekBody(r *http.Request) []byte {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, crs.BodyLimit))
	r.Body = Rejoin(b, r.Body)
	if err != nil {
		return nil
	}
	return b
}

// Verdict is every rule and category behind the decision: the spm matches,
// then CRS's rules (as CRS-<id>) and families; when CRS blocked and the spm
// score did not, CRS's come first, since the first category is the one the
// block page and the alert name. CRS rules the policy observes come last.
func (in *Inspection) Verdict() (ruleIDs, categories []string) {
	ruleIDs, categories = Summarize(in.Matches)
	if in.CRS == nil {
		return ruleIDs, categories
	}
	if len(in.CRS.Rules) > 0 {
		crsIDs := prefixed(in.CRS.Rules)
		crsCats := crs.Categories(in.CRS.Rules)
		if in.CRS.Blocked && !in.Eng.Blocked(in.Score) {
			ruleIDs, categories = append(crsIDs, ruleIDs...), append(crsCats, categories...)
		} else {
			ruleIDs, categories = append(ruleIDs, crsIDs...), append(categories, crsCats...)
		}
	}
	if len(in.CRS.Observed) > 0 {
		ruleIDs = append(ruleIDs, prefixed(in.CRS.Observed)...)
		for _, c := range crs.Categories(in.CRS.Observed) {
			if !contains(categories, c) {
				categories = append(categories, c)
			}
		}
	}
	return ruleIDs, categories
}

func prefixed(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = "CRS-" + id
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Add records a signal and its contribution to the score, under the policy:
// a rule it takes off is dropped, a rule or category it observes scores 0.
func (in *Inspection) Add(m engine.MatchResult) {
	if a := in.applied; a != nil {
		if a.Skip(m.RuleID) {
			in.Excepted = append(in.Excepted, m.RuleID)
			return
		}
		if a.ObserveMatch(m.RuleID, m.Category) {
			m.Score = 0
		}
	}
	in.Matches = append(in.Matches, m)
	in.Score += m.Score
}

// Scan runs the signature scan and, unless the URL is cached as clean, the
// domain reputation check. The heuristics run separately (Heuristics), after
// the caller has computed the entropy of what Scan read.
func (in *Inspection) Scan(r *http.Request) {
	in.filter(r)
	in.scanSignatures(r)
	if !in.URLCached {
		in.scanDomainReputation(r.Host)
	}
}

// connectCategories are the request-rule categories a CONNECT is matched
// against. Its whole content is host:port, and command or tool names in a
// host name (ifconfig.me, ipconfig.io, metasploit.com) are not command
// injection: on 198,649 real hosts (Tranco crawl) every block came from
// such a name. SSRF stays (169.254.169.254, the metadata names, ports such
// as 22 or 6379); the domain reputation checks and the heuristics run as
// for any request.
var connectCategories = map[string]bool{"SSRF": true}

// scanSignatures runs the regex rule set over the URL, the inspected headers
// and, if nothing has crossed the threshold yet, the request body.
func (in *Inspection) scanSignatures(r *http.Request) {
	var only map[string]bool
	if r.Method == http.MethodConnect {
		only = connectCategories
	}
	// On a safe-cache hit the URL already scored zero; scan the rest.
	normalizedURL := ""
	if !in.URLCached {
		normalizedURL = engine.NormalizeInput(in.RawURL)
	}

	headerStr, n := InspectedHeaderText(r.Header)
	in.HeaderCount += n

	// Combine URL + headers for scoring
	combined := normalizedURL + " " + engine.NormalizeInput(headerStr)
	in.match(r, combined, only)

	// Also check raw (pre-decoded) URL for encoded evasion patterns like %c0%af
	// that get decoded by engine.NormalizeInput and lose their detectable pattern
	if !in.URLCached && !in.WouldBlock() && in.RawURL != normalizedURL {
		rawMatches, rawSkipped, rawScore := in.Eng.MatchRulesFiltered(in.RawURL, only, in.ruleFilter(r))
		if rawScore > 0 {
			in.Matches = append(in.Matches, rawMatches...)
			in.Score += rawScore
		}
		in.Excepted = append(in.Excepted, rawSkipped...)
	}

	if !in.WouldBlock() {
		in.scanBody(r)
	}
}

// scanBody inspects the request body, up to MaxBodyInspectSize, and restores it
// so the request can still be forwarded. Bodies of types the rule set cannot
// meaningfully match are skipped.
func (in *Inspection) scanBody(r *http.Request) {
	if r.Body == nil || !engine.ShouldInspectBody(r.Header.Get("Content-Type")) {
		return
	}
	// Read one byte past the inspection limit so we can tell whether the body
	// was truncated (i.e. a payload may be hiding past the limit).
	bodyBytes, readErr := io.ReadAll(io.LimitReader(r.Body, MaxBodyInspectSize+1))
	if readErr != nil || len(bodyBytes) == 0 {
		return
	}
	// The request is forwarded whole: what was read goes back in front of
	// what was not. Only the first MaxBodyInspectSize bytes are inspected.
	r.Body = Rejoin(bodyBytes, r.Body)
	truncated := len(bodyBytes) > MaxBodyInspectSize
	if truncated {
		bodyBytes = bodyBytes[:MaxBodyInspectSize]
	}
	in.bodyRaw, in.bodyRead = bodyBytes, true
	in.BodyStr = engine.NormalizeInput(string(bodyBytes))
	in.BodySize = len(bodyBytes)

	// A text/plain body is pasted text far more often than a form: code,
	// logs, notes. The injection and target categories are observe-only on
	// it (textPlainObserveOnly): their matches are recorded with no score,
	// so they show in the observe log and the traffic log and never block.
	// On 8,051 prowl hard negatives uploaded as text/plain they were behind
	// most of the false positives.
	var only map[string]bool
	if isTextPlain(r.Header.Get("Content-Type")) {
		only = textPlainScored()
	}
	in.match(r, in.BodyStr, only)
	if only != nil {
		observed, skipped, _ := in.Eng.MatchRulesFiltered(in.BodyStr, textPlainObserveOnly, in.ruleFilter(r))
		for _, m := range observed {
			m.Score = 0
			in.Matches = append(in.Matches, m)
		}
		in.Excepted = append(in.Excepted, skipped...)
	}

	// An over-limit body is a coverage gap, not a clean allow. Add a
	// corroborating signal (below the block threshold, so it can't block on its
	// own; pairs with any other rule/heuristic hit). The caller counts it.
	if truncated {
		in.BodyTruncated = true
		const oversizeBodyScore = 4
		in.Add(engine.MatchResult{RuleID: "WAF-BODY-OVERSIZE", Category: "BODY_OVERSIZE", Score: oversizeBodyScore})
	}
}

// scanDomainReputation applies the ML-lite signals: DGA and typosquatting.
//
// Both are probabilistic, so each contributes LESS than the block threshold and
// cannot block on its own; corroboration from another signal or a signature
// rule is required. That is what keeps a typosquat near-miss on a real domain
// observed rather than blocked.
func (in *Inspection) scanDomainReputation(host string) {
	if in.WouldBlock() || host == "" {
		return
	}
	const dgaScore, typoScore = 6, 5

	if in.Eng.CategoryEnabled("DGA_DOMAIN") {
		if dgaResult := in.Eng.AnalyzeDGACached(host); dgaResult.IsDGA {
			in.Add(engine.MatchResult{RuleID: "ML-DGA-001", Category: "DGA_DOMAIN", Score: dgaScore})
			in.DGA = &dgaResult
		}
	}
	if in.Eng.CategoryEnabled("TYPOSQUATTING") {
		if typoResult := engine.CheckTyposquat(host); typoResult.Suspicious {
			in.Add(engine.MatchResult{RuleID: "ML-TYPO-001", Category: "TYPOSQUATTING", Score: typoScore})
			in.Typo = &typoResult
		}
	}
}

// Heuristics runs the stateful, time-windowed behavioural checks. They are
// scored against the entropy of the body and the URL, which is why they run
// after the caller has built its traffic feature rather than inside Scan.
func (in *Inspection) Heuristics(r *http.Request, bodyEntropy, urlEntropy float64) {
	hResults, hScore := in.Eng.CheckRequestHeuristics(
		in.ClientIP, r.Method, r.Host, r.URL.Path,
		in.BodyStr, in.BodySize, bodyEntropy, urlEntropy,
	)
	if in.filter(r) == nil {
		for _, hr := range hResults {
			in.Matches = append(in.Matches, engine.MatchResult{
				Category: hr.Category,
				RuleID:   hr.ID,
				Pattern:  hr.Detail,
				Score:    hr.Score,
			})
		}
		// The returned total is used rather than re-summing the results. It is the
		// same number today (every heuristic that appends a result also adds its
		// score) but taking the function at its word keeps this independent of
		// that internal detail.
		in.Score += hScore
		return
	}
	// Under a policy each result goes through Add, which can take it off or
	// observe it, so the score is the sum of what Add kept.
	for _, hr := range hResults {
		in.Add(engine.MatchResult{Category: hr.Category, RuleID: hr.ID, Pattern: hr.Detail, Score: hr.Score})
	}
}

// Summarize flattens the matches into the rule IDs and the de-duplicated
// categories, preserving first-seen order: the first category is what the
// block page and the alert report as the primary one.
func Summarize(matches []engine.MatchResult) (ruleIDs, categories []string) {
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

// Rejoin puts bytes already read from a body back in front of the rest of
// it, so a message that was partly read for inspection is forwarded whole.
func Rejoin(read []byte, rest io.ReadCloser) io.ReadCloser {
	if rest == nil {
		return io.NopCloser(bytes.NewReader(read))
	}
	return struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(read), rest), rest}
}

// Evaluate runs a full request inspection the way handleReqmod does, without
// its side effects and without the safe-URL cache (a first sight of every
// URL). It reports lanSkipped when the destination is a LAN host, which the
// handler lets through uninspected. TestEvaluateMatchesHandleReqmod holds
// the two paths to the same verdict.
func Evaluate(eng *engine.Engine, crsEng *crs.Engine, pol *policy.Policy, r *http.Request, clientIP string) (in *Inspection, lanSkipped bool) {
	in = &Inspection{Eng: eng, CRSEng: crsEng, Policy: pol, RawURL: r.URL.String(), ClientIP: clientIP}
	if engine.IsLANHost(r.Host) {
		return in, true
	}
	in.Scan(r)
	in.Heuristics(r, engine.ShannonEntropy(in.BodyStr), engine.ShannonEntropy(in.RawURL))
	in.RunCRS(r)
	return in, false
}

// dangerousResponseTypes are response content types blocked outright.
var dangerousResponseTypes = []string{
	"application/x-msdownload", "application/x-dosexec",
	"application/x-executable", "application/x-sharedlib",
	"application/java-archive", "application/x-ms-shortcut",
}

// ResponseVerdict is the response half of the WAF verdict.
type ResponseVerdict struct {
	Blocked  bool
	Score    int
	Rules    []string
	Category string
	// Uninspectable is a compressed text body the rules cannot read; the
	// caller counts it and lets the response through.
	Uninspectable bool
}

// EvaluateResponse decides on a response the way handleRespmod does: a
// dangerous content type blocks outright, a compressed text body is
// uninspectable, a text body is matched against the response rules and the
// PII heuristic, up to MaxBodyInspectSize. The body is put back whole.
func EvaluateResponse(eng *engine.Engine, resp *http.Response) ResponseVerdict {
	contentType := resp.Header.Get("Content-Type")
	contentTypeLower := strings.ToLower(contentType)
	for _, dt := range dangerousResponseTypes {
		if strings.Contains(contentTypeLower, dt) {
			return ResponseVerdict{Blocked: true, Score: 10, Category: "DANGEROUS_CONTENT_TYPE"}
		}
	}
	// Compressed text bodies are uninspectable by the regex rules (they'd
	// match against compressed bytes). Flag the coverage gap rather than
	// silently returning a clean verdict.
	if resp.Body != nil && engine.IsTextContent(contentType) && engine.IsCompressedEncoding(resp.Header.Get("Content-Encoding")) {
		return ResponseVerdict{Uninspectable: true}
	}
	var v ResponseVerdict
	if resp.Body != nil && engine.IsTextContent(contentType) {
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyInspectSize))
		resp.Body = Rejoin(bodyBytes, resp.Body)
		if err == nil && len(bodyBytes) > 0 {
			body := string(bodyBytes)
			v.Score, v.Rules, v.Category = eng.MatchResponseRules(body)
			// H3: PII counter heuristic on response body
			piiResults, _ := eng.CheckResponseHeuristics(body)
			for _, pr := range piiResults {
				v.Score += pr.Score
				v.Rules = append(v.Rules, pr.ID)
				if v.Category == "" {
					v.Category = pr.Category
				}
			}
			v.Blocked = eng.Blocked(v.Score)
		}
	}
	return v
}
