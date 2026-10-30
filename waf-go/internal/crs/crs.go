// Package crs is the OWASP Core Rule Set half of the WAF verdict: Coraza
// with CRS at paranoia 1, configured for a forward proxy. The WAF and the
// wafeval measurement harness run the same directives from here.
package crs

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"

	"secure-proxy-waf/internal/engine"
)

// BodyLimit is how much of a request body CRS reads: the WAF's inspection
// limit, inspected partially beyond it rather than refused.
const BodyLimit = 1 << 20

// Adjustments for a forward proxy, each one a choice the report has to name
// (text/plain bodies go to the RAW body processor: parsed as urlencoded, a
// pasted text became one argument name and its line breaks a header
// injection, 921150, on 1,441 of 8,051 prowl hard negatives; and on them
// 921110, request smuggling, is off: a pasted access log is full of
// request lines):
//   - CONNECT is a normal method here (HTTPS without bump is nothing else),
//     so it joins CRS's allowed methods.
//   - The request is given to CRS in origin form (path and query, plus
//     Host), as a reverse-proxy WAF sees it; Squid hands the WAF the
//     absolute form.
//   - The request body limit is the WAF's 1 MiB inspection limit, and a
//     longer body is inspected up to it rather than refused.
//   - A body that is not a form, multipart, JSON or XML goes to the RAW
//     processor too. CRS asks Coraza to parse such a body (901340), and
//     Coraza parses it as urlencoded: any multi-line body (NDJSON log
//     shipping, a Sentry envelope, CSV, a binary upload) then has argument
//     names with line breaks, which 921150 blocks on its own. JSON (with
//     the +json types) and the XML types coraza.conf-recommended names keep
//     their processing.
//
// policyRemovals takes out the CRS rules that enforce what an application
// accepts, which on an egress proxy is the destination's business, not
// ours: allowed request content types (920420: text/plain is what
// navigator.sendBeacon posts), restricted headers (920450, 920451) and
// allowed charsets (920480). The
// protocol rules that flag malformed requests stay.
// Removed too: the session-fixation rules
// 943110 and 943120 (a session_id sent to a third-party site, with that
// site's referer, is how a session works) and 930130 (restricted file
// names in the path: /config/x.json and /sys/images/ on someone's CDN).
// They protect the application's own sessions and files.
// And 932370, Windows command injection: on real
// traffic it fired on long tracking parameters (LinkedIn collect,
// prev_scp, tracking_data), 33 false positives against at most 9 true.
//
// 920440 (restricted file extensions) was removed with the policy rules
// and is back: measured on its own it caught 2,279 of CSIC's attacks
// (requests for .bak, .old, .inc files) for 9 false positives on 59,816
// real requests. It runs on egressExtensions.
const policyRemovals = "SecRuleRemoveById 920420 920450 920451 920480 943110 943120 930130 932370\n" +
	// us_privacy is the IAB CCPA string, "1---" when no choice applies: it
	// reads as an SQL comment to libinjection (942100), on any page with a
	// US consent banner (576 of 59,816 Tranco requests).
	// Sites give it many names (us_privacy, usp, uspstring, uspConsent,
	// usps, sst.us_privacy, AV_CCPA): any argument whose name holds usp,
	// privacy or ccpa.
	"SecRuleUpdateTargetById 942100 \"!ARGS:/(?i)(usp|privacy|ccpa)/\"\n" +
	// Cloudflare's image resizing takes its options in the path
	// (/cdn-cgi/image/width=640,onerror=redirect/...), and onerror=redirect
	// reads as an event handler to 941120: 6 of 59,816 Tranco requests on
	// 6 hosts, 4 of them blocked by it alone. The path leaves 941120 under
	// that prefix only; the arguments, and the other XSS rules on the path,
	// still apply.
	"SecRule REQUEST_FILENAME \"@beginsWith /cdn-cgi/image/\" \"id:1000110,phase:1,pass,t:none,nolog,ctl:ruleRemoveTargetById=941120;REQUEST_FILENAME\"\n"

// egressExtensions replaces CRS's restricted_extensions for 920440. The
// default list names files a client downloads on
// its own through an egress proxy: a CA's intermediate certificate (.crt,
// .cer, .pem), debug symbols (.pdb, .dll), install scripts (.sh, .bat, .cmd),
// data files (.dat, .db, .sql), and .com, which is any domain name in a path
// (14 of 15 false positives measured). What stays is what a client has no
// reason to fetch: backup and temporary copies, and server-side files that
// are never served as is. CSIC's 2,279 hits were .old 792, .inc 687,
// .bak 653, .htr 59, .cnf 54 and .dll 34: all but the .dll ones stay.
// It is set before the CRS rules load, so 901's default does not apply.
const egressExtensions = "SecAction \"id:900240,phase:1,pass,t:none,nolog,setvar:'tx.restricted_extensions=" +
	".old/ .bak/ .backup/ .back/ .bck/ .bk/ .bkp/ .copy/ .sav/ .save/ .swp/ .swo/ .swap/ .tmp/ .temp/ .dist/ .dpkg-dist/ " +
	".inc/ .htr/ .htw/ .ida/ .idc/ .idq/ .printer/ .asa/ .asax/ .ascx/ .cdx/ .licx/ .resources/ .resx/ .webinfo/ .vsdisco/ .config/ .cnf/'\"\n"

// Options choose the paranoia level and, for wafeval's ablation runs only,
// undo the forward-proxy adjustments. The WAF uses Options{Paranoia: 1}.
type Options struct {
	Paranoia int
	// KeepPolicy leaves CRS as shipped: no policy removals, no exclusions,
	// the default restricted extensions.
	KeepPolicy bool
	// Restore takes single rule IDs back out of the removal list, so each
	// removal can be measured on its own.
	Restore map[string]bool
	// extra is appended after the rules load; tests use it to break the
	// configuration.
	extra string
}

// Engine is a compiled CRS configuration. It is safe for concurrent use: each
// Inspect runs in its own transaction.
type Engine struct {
	waf      coraza.WAF
	paranoia int
}

// New compiles the rule set. An error means the WAF has no CRS half and must
// not pretend otherwise.
func New(o Options) (*Engine, error) {
	if o.Paranoia < 1 || o.Paranoia > 4 {
		return nil, fmt.Errorf("paranoia level %d: want 1 to 4", o.Paranoia)
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(directives(o)))
	if err != nil {
		return nil, fmt.Errorf("loading the OWASP Core Rule Set: %w", err)
	}
	tx := waf.NewTransaction()
	_, ok := tx.(remover)
	_ = tx.Close()
	if !ok {
		return nil, errors.New("this Coraza's transactions cannot remove a rule per request: the WAF's exceptions would do nothing")
	}
	return &Engine{waf: waf, paranoia: o.Paranoia}, nil
}

func directives(o Options) string {
	setup, removals := egressExtensions, policyRemovals
	if o.KeepPolicy {
		setup, removals = "", ""
	} else if len(o.Restore) > 0 {
		removals = restored(o.Restore)
	}
	return fmt.Sprintf(`
Include @coraza.conf-recommended
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecAuditEngine Off
Include @crs-setup.conf.example
SecRule REQUEST_HEADERS:Content-Type "@rx ^text/plain" "id:1000100,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=RAW,ctl:ruleRemoveById=921110"
SecRule REQUEST_HEADERS:Content-Type "!@rx ^(?:application/x-www-form-urlencoded|multipart/form-data|application/(?:[a-z0-9.!#$&^_-]+\+)?json|(?:application(?:/soap\+|/)|text/)xml)" "id:1000102,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=RAW"
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"
SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS CONNECT PUT PATCH DELETE'"
%sInclude @owasp_crs/*.conf
%s%s`, BodyLimit, BodyLimit, o.Paranoia, setup, removals, o.extra)
}

func restored(restore map[string]bool) string {
	lines := strings.SplitAfter(policyRemovals, "\n")
	var kept []string
	for _, id := range strings.Fields(strings.TrimPrefix(lines[0], "SecRuleRemoveById")) {
		if !restore[id] {
			kept = append(kept, id)
		}
	}
	out := ""
	if len(kept) > 0 {
		out = "SecRuleRemoveById " + strings.Join(kept, " ") + "\n"
	}
	return out + strings.Join(lines[1:], "")
}

// Paranoia is the blocking paranoia level.
func (e *Engine) Paranoia() int { return e.paranoia }

// Result is what CRS decided about one request.
type Result struct {
	Blocked bool
	// Score is CRS's inbound anomaly score (5 blocks at paranoia 1), less
	// what observed rules added; set when the request is blocked.
	Score int
	// Rules are the IDs of the matched rules that scored, sorted. Observed
	// rules are not among them.
	Rules []string
	// Observed are the matched rules the policy leaves to log only, sorted.
	Observed []string
	// Inbound is the anomaly score CRS itself computed, observed rules
	// included, blocked or not.
	Inbound int
	// Contrib is what each matched scoring rule added to Inbound by its
	// severity, once per variable matched by the link of the chain that
	// scores. Inbound == the sum of Contrib is what lets an observed rule's
	// share be taken off (wafeval checks it).
	Contrib map[string]int
	// Explain is, when asked for, what each scoring rule matched.
	Explain []string
	// Targets are, on a block, the variable and key each scoring rule
	// matched itself (not through a chained link): what an exception for it
	// would name. The alert carries them, so a block in the logs can be
	// turned into an exception for one argument.
	Targets []Target
}

// Target is one variable a rule matched, as a policy exception names it.
type Target struct {
	Rule     int
	Variable string
	Key      string
}

// Name is the target as a policy exception writes it: VARIABLE or
// VARIABLE:key. A key the policy would read as a regex (/.../) is written as
// a regex that matches that key alone; the policy compares keys lowercased.
func (t Target) Name() string {
	if t.Key == "" {
		return t.Variable
	}
	if len(t.Key) > 1 && strings.HasPrefix(t.Key, "/") && strings.HasSuffix(t.Key, "/") {
		return t.Variable + ":/^" + regexp.QuoteMeta(strings.ToLower(t.Key)) + "$/"
	}
	return t.Variable + ":" + t.Key
}

// Exclusion takes one rule, or one target of it, out of one transaction:
// Coraza's ctl:ruleRemoveById and ctl:ruleRemoveTargetById, chosen per
// request by the WAF's policy.
type Exclusion struct {
	Rule int
	// Target set: only Variable (and Key or KeyRx, when given) is removed
	// from the rule; otherwise the whole rule is.
	Target   bool
	Variable variables.RuleVariable
	Key      string
	KeyRx    *regexp.Regexp
}

// Policy is what the WAF's policy asks of one transaction.
type Policy struct {
	Exclusions []Exclusion
	// Observe reports whether a rule only logs: it runs and is reported,
	// and what it added to the anomaly score is taken off before the
	// decision. Nil: none.
	Observe func(id int) bool
}

// remover is the part of Coraza's transaction that ctl actions use. It is
// not in the public Transaction interface; New checks it is there, so a
// Coraza that drops it stops the WAF instead of ignoring every exception.
type remover interface {
	RemoveRuleByID(id int)
	RemoveRuleTargetByID(id int, variable variables.RuleVariable, key string, keyRx *regexp.Regexp)
}

// Severity weights, as crs-setup.conf.example sets them: the anomaly score
// a rule of each severity adds per matched variable.
var severityWeight = map[types.RuleSeverity]int{
	types.RuleSeverityCritical: 5,
	types.RuleSeverityError:    4,
	types.RuleSeverityWarning:  3,
	types.RuleSeverityNotice:   2,
}

// Inspect runs a request through CRS with no policy.
func (e *Engine) Inspect(r *http.Request, body []byte, clientIP string, explain bool) Result {
	return e.InspectWith(r, body, clientIP, explain, Policy{})
}

// InspectWith runs a request through CRS under a policy. body is the request
// body as read so far, at most BodyLimit bytes of it; r.Body is not read.
// CONNECT and LAN destinations are the caller's business: CRS has nothing to
// say about a host name, and the WAF lets the LAN through uninspected.
func (e *Engine) InspectWith(r *http.Request, body []byte, clientIP string, explain bool, pol Policy) Result {
	tx := e.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()
	if len(pol.Exclusions) > 0 {
		rm := tx.(remover) // checked in New
		for _, x := range pol.Exclusions {
			if x.Target {
				rm.RemoveRuleTargetByID(x.Rule, x.Variable, x.Key, x.KeyRx)
			} else {
				rm.RemoveRuleByID(x.Rule)
			}
		}
	}
	tx.ProcessConnection(clientIP, 40000, "203.0.113.1", 443)
	// Bare ${NAME} macros (unexpanded ad-tech placeholders) are rewritten
	// to NAME in the URI CRS reads: CRS takes ${...} for a shell or PHP
	// expression (932130, 933135), on 297 of 59,816 real requests. Shell
	// evasion variables are left as they are.
	uri := engine.NeutralizeBareMacros(r.URL.RequestURI())
	if r.Method == http.MethodConnect {
		uri = r.Host
	}
	tx.ProcessURI(uri, r.Method, r.Proto)
	tx.AddRequestHeader("Host", r.Host)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	// net/http takes Transfer-Encoding out of the header map into
	// r.TransferEncoding when it parses the encapsulated request, so a
	// chunked POST would reach CRS with neither framing header: 920180,
	// "POST without Content-Length and Transfer-Encoding".
	if len(r.TransferEncoding) > 0 && r.Header.Get("Transfer-Encoding") == "" {
		tx.AddRequestHeader("Transfer-Encoding", strings.Join(r.TransferEncoding, ", "))
	} else if r.ContentLength > 0 && r.Header.Get("Content-Length") == "" {
		tx.AddRequestHeader("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	it := tx.ProcessRequestHeaders()
	if it == nil {
		// Phase 2, where the arguments are matched and the anomaly score
		// is evaluated, runs for every request, with a body or without.
		if it2, _, err := tx.ReadRequestBodyFrom(bytes.NewReader(body)); err == nil && it2 != nil {
			it = it2
		}
		if it == nil {
			if it3, err := tx.ProcessRequestBody(); err == nil {
				it = it3
			}
		}
	}
	matched := tx.MatchedRules()
	res := Result{Blocked: it != nil, Inbound: txInt(tx, "blocking_inbound_anomaly_score")}
	observedShare := 0
	for _, m := range matched {
		id, ok := scoringID(m.Rule())
		if !ok {
			continue
		}
		w := severityWeight[m.Rule().Severity()] * scoredMatches(m.MatchedDatas())
		if res.Contrib == nil {
			res.Contrib = map[string]int{}
		}
		res.Contrib[strconv.Itoa(id)] += w
		if pol.Observe != nil && pol.Observe(id) {
			observedShare += w
			res.Observed = append(res.Observed, strconv.Itoa(id))
			continue
		}
		res.Rules = append(res.Rules, strconv.Itoa(id))
	}
	sort.Strings(res.Rules)
	sort.Strings(res.Observed)
	if res.Blocked && observedShare > 0 {
		// The decision is taken again without what the observed rules added.
		// It can only turn a block into a pass: an observed rule never
		// blocks, and a threshold that cannot be read leaves CRS's decision.
		if th := txInt(tx, "inbound_anomaly_score_threshold"); th > 0 {
			res.Blocked = res.Inbound-observedShare >= th
		}
	}
	if res.Blocked {
		res.Score = res.Inbound - observedShare
		seen := map[Target]bool{}
		for _, m := range matched {
			if m.Rule().Severity() == types.RuleSeverityUnset {
				continue
			}
			for _, d := range m.MatchedDatas() {
				if explain {
					res.Explain = append(res.Explain, fmt.Sprintf("%d: %s:%s=%s", m.Rule().ID(), d.Variable().Name(), d.Key(), clip(d.Value(), 90)))
				}
				t := Target{Rule: m.Rule().ID(), Variable: d.Variable().Name(), Key: d.Key()}
				if d.ChainLevel() == 0 && !seen[t] {
					seen[t] = true
					res.Targets = append(res.Targets, t)
				}
			}
		}
	}
	return res
}

// scoredMatches is how many times a matched rule added its weight. Coraza
// runs a rule's setvar once per matched variable, and in a chain each link
// runs its own: CRS scores in the last link (920440 sets tx.extension in the
// first link and the anomaly score in the second), so only the variables
// the deepest link matched count. A rule with no chain is all level 0.
func scoredMatches(ds []types.MatchData) int {
	deepest, n := -1, 0
	for _, d := range ds {
		switch l := d.ChainLevel(); {
		case l > deepest:
			deepest, n = l, 1
		case l == deepest:
			n++
		}
	}
	return max(1, n)
}

// txInt reads a numeric TX variable; 0 when the transaction does not expose
// it or it is not a number.
func txInt(tx types.Transaction, name string) int {
	st, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return 0
	}
	for _, v := range st.Variables().TX().Get(name) {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// scoringID is the ID of a matched rule that carries a severity, which in CRS and
// in coraza.conf-recommended is what a scoring or blocking rule has. Setup
// rules (900xxx, 901xxx), the paranoia-level gates (9xx011 to 9xx018) and
// the blocking evaluation (949xxx, 980xxx) carry none, so a false positive
// is attributed to the rule that scored, not to the machinery around it.
func scoringID(r types.RuleMetadata) (int, bool) {
	if r.Severity() == types.RuleSeverityUnset {
		return 0, false
	}
	if id := r.ID(); id >= 949000 && id < 950000 || id >= 980000 && id < 981000 {
		return 0, false
	}
	return r.ID(), true
}

// families name the CRS rule files by what they detect. A block is reported
// under the family of its rules, so the block page, the statistics and the
// alerts say what kind of attack CRS saw rather than a rule number.
var families = map[string]string{
	"911": "CRS_METHOD", "913": "CRS_SCANNER", "920": "CRS_PROTOCOL", "921": "CRS_PROTOCOL_ATTACK",
	"922": "CRS_MULTIPART", "930": "CRS_LFI", "931": "CRS_RFI", "932": "CRS_RCE", "933": "CRS_PHP",
	"934": "CRS_GENERIC", "941": "CRS_XSS", "942": "CRS_SQLI", "943": "CRS_SESSION", "944": "CRS_JAVA",
}

// Categories are the families of rule IDs, in the order of the IDs, each once.
// An ID outside the known files (coraza.conf-recommended's 200xxx) is CRS.
func Categories(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		cat := "CRS"
		if len(id) == 6 {
			if f, ok := families[id[:3]]; ok {
				cat = f
			}
		}
		if !seen[cat] {
			seen[cat] = true
			out = append(out, cat)
		}
	}
	return out
}
