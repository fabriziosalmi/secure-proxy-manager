package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"secure-proxy-waf/internal/crs"
	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/inspect"
	"secure-proxy-waf/internal/policy"
)

// Verdict is what one engine decided about one request.
type Verdict struct {
	Blocked    bool
	Score      int
	Rules      []string
	Categories []string
	// LANSkipped is true when the destination is a LAN host, which the
	// production handler lets through without inspecting.
	LANSkipped bool
	// Uninspectable is a compressed text response the rules cannot read.
	Uninspectable bool
	// NotInspected is true when the engine has no response inspection.
	NotInspected bool
	// Signals are the detectors that scored on this record, blocked or not,
	// each named once: an spm category (a rule set, DGA_DOMAIN, a
	// heuristic), or CRS when one of its rules scored.
	Signals []string
	// Explain is, with -explain, what each matched rule matched: "rule:
	// matched text", truncated.
	Explain []string

	// crsRan: CRS inspected the request; crsInbound is the anomaly score it
	// computed and crsContrib each scoring rule's weighted share, so the
	// report can check that the one is the sum of the other.
	crsRan     bool
	crsInbound int
	crsContrib map[string]int
	// exceptions, with -emit-exceptions on a blocked request: one per rule
	// that scored, for this host (and, for a CRS rule, the target it hit).
	exceptions []policy.Exception
}

// explainOn is set by -explain; engines fill Verdict.Explain only then.
var explainOn bool

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// spmExplain re-runs the matched request rules over the same normalized
// text the engine scanned and reports what each one matched.
func spmExplain(r *http.Request, rawURL, body string, ids []string) []string {
	text := engine.NormalizeInput(rawURL) + " " + rawURL + " " + body
	headers, _ := inspect.InspectedHeaderText(r.Header)
	text += " " + engine.NormalizeInput(headers)
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []string
	for _, cr := range engine.BlockRules() {
		for _, rule := range cr.Rules {
			if want[rule.ID] {
				out = append(out, rule.ID+": "+clip(rule.Pattern.FindString(text), 90))
			}
		}
	}
	return out
}

// Engine is a request inspector under measurement.
type Engine interface {
	Name() string
	Describe() map[string]any
	Inspect(r *http.Request, clientIP string, hello *inspect.Hello) Verdict
	InspectResponse(resp *http.Response) Verdict
}

// buildResponse turns a response record into an *http.Response, parsed by
// net/http as go-icap parses the encapsulated response.
func buildResponse(rec *Record) (*http.Response, error) {
	var b strings.Builder
	status := rec.Status
	if status == 0 {
		status = 200
	}
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for _, h := range rec.Headers {
		if len(h) != 2 || strings.EqualFold(h[0], "Content-Length") || strings.EqualFold(h[0], "Transfer-Encoding") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(rec.Body))
	b.WriteString(rec.Body)
	return http.ReadResponse(bufio.NewReader(strings.NewReader(b.String())), nil)
}

// buildRequest turns a corpus record into the bytes Squid would encapsulate
// and parses them with net/http, as go-icap does (http.ReadRequest on the
// encapsulated header block). A record the parser refuses is reported, not
// dropped: Squid would not have forwarded it either, but the count says how
// much of a dataset never reached the engine.
func buildRequest(rec *Record) (*http.Request, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", rec.Method, rec.URL)
	hasHost := false
	for _, h := range rec.Headers {
		if len(h) != 2 {
			continue
		}
		if strings.EqualFold(h[0], "Host") {
			hasHost = true
		}
		if strings.EqualFold(h[0], "Content-Length") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	if !hasHost {
		fmt.Fprintf(&b, "Host: %s\r\n", hostOf(rec))
	}
	// A browser sends Content-Length on every POST, PUT and PATCH, 0 when
	// there is no body; datasets that keep no bodies (Tranco) would
	// otherwise read as bodyless POSTs, which CRS flags (920180).
	if rec.Body != "" || rec.Method == http.MethodPost || rec.Method == http.MethodPut || rec.Method == http.MethodPatch {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(rec.Body))
	}
	b.WriteString("\r\n")
	b.WriteString(rec.Body)
	return http.ReadRequest(bufio.NewReader(strings.NewReader(b.String())))
}

// hostOf is the Host header for a record that carries none: the authority of
// the request URL, or the CONNECT target itself.
func hostOf(rec *Record) string {
	if rec.Method == http.MethodConnect {
		return rec.URL
	}
	u := rec.URL
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	return u
}

// spmEngine is the production engine, driven through the same
// inspect.Inspection calls handleReqmod makes, in the same order.
type spmEngine struct {
	eng *engine.Engine
	cfg engine.Config
	// crs is set for the hybrid: the same inspect.Evaluate call then runs
	// the CRS half too, as handleReqmod does with WAF_ENGINE=hybrid.
	crs *crs.Engine
}

func newSPMEngine(disabledHeuristics, disabledCategories, observeCategories []string) (*spmEngine, error) {
	engine.LoadCustomRules(engine.DefaultCustomRulesPath)
	engine.BuildPrefilter()
	cfg := engine.Config{Heuristics: engine.HeuristicsFromEnv(), DisabledCategories: disabledCategories, ObserveCategories: observeCategories}
	e := &spmEngine{eng: engine.New(cfg), cfg: cfg}
	for _, h := range disabledHeuristics {
		if !e.eng.SetHeuristicEnabled(h, false) {
			return nil, fmt.Errorf("unknown heuristic %q", h)
		}
	}
	return e, nil
}

func (e *spmEngine) Name() string { return "spm" }

func (e *spmEngine) Describe() map[string]any {
	rules, cats := 0, 0
	for _, cr := range engine.BlockRules() {
		rules += len(cr.Rules)
		cats++
	}
	return map[string]any{
		"block_threshold":     e.eng.BlockThreshold(),
		"request_rules":       rules,
		"request_categories":  cats,
		"disabled_categories": e.eng.DisabledCategories(),
		"observe_categories":  e.eng.ObserveCategories(),
		"heuristics":          e.eng.HeuristicStates(),
	}
}

func (e *spmEngine) InspectResponse(resp *http.Response) Verdict {
	v := inspect.EvaluateResponse(e.eng, resp)
	out := Verdict{Blocked: v.Blocked, Score: v.Score, Rules: v.Rules, Categories: []string{v.Category}, Uninspectable: v.Uninspectable}
	// A response names only its primary category: EvaluateResponse reports
	// no other.
	if v.Score > 0 {
		out.Signals = []string{v.Category}
	}
	return out
}

func (e *spmEngine) Inspect(r *http.Request, clientIP string, hello *inspect.Hello) Verdict {
	in, lan := evaluate(e.eng, e.crs, r, clientIP, hello)
	if lan {
		return Verdict{LANSkipped: true}
	}
	rules, cats := inspect.Summarize(in.Matches)
	v := Verdict{Blocked: in.Blocked(), Score: in.Score, Rules: rules, Categories: cats, Signals: signals(in)}
	if explainOn && in.Eng.Blocked(in.Score) {
		v.Explain = spmExplain(r, in.RawURL, in.BodyStr, rules)
	}
	if in.CRS != nil {
		v.Rules = append(v.Rules, in.CRS.Rules...)
		sort.Strings(v.Rules)
		v.Explain = append(v.Explain, in.CRS.Explain...)
		v.crsRan, v.crsInbound, v.crsContrib = true, in.CRS.Inbound, in.CRS.Contrib
	}
	if emitOn && in.WouldBlock() {
		v.exceptions = exceptionsFor(in, policy.RequestHost(r.Host), r.URL.Path)
	}
	return v
}

// signals names, once each, the spm categories whose matches scored and CRS
// when one of its rules scored. A stage skipped because an earlier one
// already blocks (CRS, the base64 pass) signals nothing.
func signals(in *inspect.Inspection) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range in.Matches {
		if m.Score > 0 && !seen[m.Category] {
			seen[m.Category] = true
			out = append(out, m.Category)
		}
	}
	if in.CRS != nil && len(in.CRS.Rules) > 0 {
		out = append(out, "CRS")
	}
	return out
}

// emitOn is set by -emit-exceptions.
var emitOn bool

// exceptionsFor names one exception per rule that scored on a blocked
// request: a CRS rule for the host and each target it matched, an spm rule
// for the host and the request's path. An spm rule has no target to narrow
// it. Even so an exception is a decision, not a fix: a benign upload and the
// attacks it resembles can share one URL and differ only in the body, and
// then no exception separates them (EXFIL-007 on prowlbench's one upload
// endpoint let 38 of its 46 detected attacks through).
func exceptionsFor(in *inspect.Inspection, host, path string) []policy.Exception {
	var out []policy.Exception
	if path == "" {
		path = "/"
	}
	for _, m := range in.Matches {
		if m.Score > 0 {
			out = append(out, policy.Exception{Rule: m.RuleID, Host: host, Path: path})
		}
	}
	if in.CRS == nil || !in.CRS.Blocked {
		return out
	}
	scoring := map[string]bool{}
	for _, id := range in.CRS.Rules {
		scoring[id] = true
	}
	for _, t := range in.CRS.Targets {
		id := strconv.Itoa(t.Rule)
		if !scoring[id] {
			continue
		}
		out = append(out, policy.Exception{Rule: "CRS-" + id, Host: host, Target: t.Name()})
	}
	return out
}

// evalPolicy is the -policy file, nil without one.
var evalPolicy *policy.Policy

// evaluate is inspect.Evaluate under -policy, with -explain passed to CRS.
func evaluate(eng *engine.Engine, c *crs.Engine, r *http.Request, clientIP string, hello *inspect.Hello) (*inspect.Inspection, bool) {
	if !explainOn || c == nil {
		return inspect.EvaluateHello(eng, c, evalPolicy, r, clientIP, hello)
	}
	in := &inspect.Inspection{Eng: eng, CRSEng: c, Policy: evalPolicy, Explain: true, RawURL: r.URL.String(), ClientIP: clientIP, Hello: hello}
	if engine.IsLANHost(r.Host) {
		return in, true
	}
	in.Scan(r)
	in.Heuristics(r, engine.ShannonEntropy(in.BodyStr), engine.ShannonEntropy(in.RawURL))
	in.RunCRS(r)
	return in, false
}

// readBody reads r's body and puts it back, for an engine that needs the
// bytes and leaves the request as it found it.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}
