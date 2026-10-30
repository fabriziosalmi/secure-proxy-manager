// Package policy is the operator's say over single rules: log-only (for the
// whole WAF, a category or one rule) and exceptions that take one rule off one
// host, path or argument. It is read from a file the WAF watches, so a false
// positive can be switched off without restarting the WAF and without
// switching off the category the rule belongs to.
//
// A Policy is immutable once built. The WAF swaps the pointer on a reload,
// and each request reads it once, so no request sees half of two policies.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types/variables"

	"secure-proxy-waf/internal/crs"
)

// DefaultPath is where the WAF looks for the policy: the configuration
// directory it already mounts read-only.
const DefaultPath = "/config/waf_policy.json"

// Limits on what one file may hold, so a mistaken file cannot make every
// request walk a list of millions.
const (
	MaxFileSize   = 1 << 20
	MaxExceptions = 10000
)

// Modes of the whole WAF.
const (
	ModeBlock   = "block"
	ModeObserve = "observe"
)

// crsPrefix is how the WAF names a Core Rule Set rule in its verdicts.
const crsPrefix = "CRS-"

// File is the JSON document, as written.
type File struct {
	Version           int         `json:"version"`
	Mode              string      `json:"mode,omitempty"`
	ObserveRules      []string    `json:"observe_rules,omitempty"`
	ObserveCategories []string    `json:"observe_categories,omitempty"`
	Exceptions        []Exception `json:"exceptions,omitempty"`
}

// Exception takes one rule off the requests it matches. Rule is required, and
// at least one of Host, Path and Target: a rule taken off everywhere is
// observe_rules, which keeps it visible.
type Exception struct {
	// Rule is an exact rule ID as the WAF reports it: CRS-942290, SQLi-015.
	Rule string `json:"rule"`
	// Host is a host name, or with a leading dot the name and every name
	// under it. Empty: any host.
	Host string `json:"host,omitempty"`
	// Path is a prefix of the URL path, starting with /. Empty: any path.
	Path string `json:"path,omitempty"`
	// Target, for a CRS rule only, narrows the exception to one variable or
	// one key of it: ARGS:password, REQUEST_HEADERS:Accept, ARGS_NAMES:/^ep\./.
	Target string `json:"target,omitempty"`
	// Comment is for the people who read the file.
	Comment string `json:"comment,omitempty"`
}

// Policy is a validated File, ready for requests.
type Policy struct {
	mode         string
	observeRules map[string]bool
	observeCats  map[string]bool
	// crsObserve are the CRS rule IDs and families that only observe.
	crsObserveIDs  map[int]bool
	crsObserveFams map[string]bool

	exact   map[string][]*rule // exceptions for one host
	suffix  map[string][]*rule // exceptions for a host and every name under it
	anyHost []*rule            // exceptions with no host

	count  int
	digest string
}

type rule struct {
	id      string
	crsID   int // 0 for an spm rule
	path    string
	hasTgt  bool
	tgtVar  variables.RuleVariable
	tgtKey  string
	tgtKeyR *regexp.Regexp
}

// Empty is the policy of a WAF with no file: block, no exceptions.
func Empty() *Policy {
	p, _ := Build(File{Version: 1}, nil)
	return p
}

// Load reads and validates the file at path. A missing file is the empty
// policy, not an error: most installations will never write one.
func Load(path string, known func(id string) bool) (*Policy, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's configured path
	if errors.Is(err, fs.ErrNotExist) {
		return Empty(), nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxFileSize {
		return nil, fmt.Errorf("%s is over %d bytes", path, MaxFileSize)
	}
	return Parse(raw, known)
}

// Parse validates a policy document. known reports whether an spm rule ID
// exists; nil accepts any. A field the format does not have is an error, so
// a misspelt "exeptions" is not a policy that silently does nothing.
func Parse(raw []byte, known func(id string) bool) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if dec.More() {
		return nil, errors.New("policy: more than one JSON document")
	}
	p, err := Build(f, known)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	p.digest = hex.EncodeToString(sum[:])
	return p, nil
}

// Build validates f. Every error names the entry it is about.
func Build(f File, known func(id string) bool) (*Policy, error) {
	if f.Version != 1 {
		return nil, fmt.Errorf("policy: version %d: want 1", f.Version)
	}
	p := &Policy{
		mode:           ModeBlock,
		observeRules:   map[string]bool{},
		observeCats:    map[string]bool{},
		crsObserveIDs:  map[int]bool{},
		crsObserveFams: map[string]bool{},
		exact:          map[string][]*rule{},
		suffix:         map[string][]*rule{},
		digest:         "empty",
	}
	switch f.Mode {
	case "", ModeBlock:
	case ModeObserve:
		p.mode = ModeObserve
	default:
		return nil, fmt.Errorf("policy: mode %q: want %q or %q", f.Mode, ModeBlock, ModeObserve)
	}
	for _, id := range f.ObserveRules {
		crsID, err := checkRule(id, known)
		if err != nil {
			return nil, fmt.Errorf("policy: observe_rules: %w", err)
		}
		p.observeRules[id] = true
		if crsID != 0 {
			p.crsObserveIDs[crsID] = true
		}
	}
	for _, cat := range f.ObserveCategories {
		if strings.TrimSpace(cat) == "" {
			return nil, errors.New("policy: observe_categories: an empty name")
		}
		p.observeCats[cat] = true
		if strings.HasPrefix(cat, "CRS") {
			p.crsObserveFams[cat] = true
		}
	}
	if len(f.Exceptions) > MaxExceptions {
		return nil, fmt.Errorf("policy: %d exceptions: at most %d", len(f.Exceptions), MaxExceptions)
	}
	for i, e := range f.Exceptions {
		r, host, sub, err := compile(e, known)
		if err != nil {
			return nil, fmt.Errorf("policy: exceptions[%d] (%s): %w", i, e.Rule, err)
		}
		switch {
		case host == "":
			p.anyHost = append(p.anyHost, r)
		case sub:
			p.suffix[host] = append(p.suffix[host], r)
		default:
			p.exact[host] = append(p.exact[host], r)
		}
	}
	p.count = len(f.Exceptions)
	return p, nil
}

// checkRule returns the numeric ID of a CRS rule, 0 for an spm rule.
func checkRule(id string, known func(string) bool) (int, error) {
	if id == "" {
		return 0, errors.New("a rule ID is required")
	}
	if rest, ok := strings.CutPrefix(id, crsPrefix); ok {
		n, err := strconv.Atoi(rest)
		if err != nil || len(rest) != 6 || n < 900000 || n > 999999 {
			return 0, fmt.Errorf("%q: a CRS rule is CRS- and six digits from 900000", id)
		}
		return n, nil
	}
	if known != nil && !known(id) {
		return 0, fmt.Errorf("%q: no such rule", id)
	}
	return 0, nil
}

func compile(e Exception, known func(string) bool) (r *rule, host string, sub bool, err error) {
	crsID, err := checkRule(e.Rule, known)
	if err != nil {
		return nil, "", false, err
	}
	if e.Host == "" && e.Path == "" && e.Target == "" {
		return nil, "", false, errors.New("no host, path or target: a rule taken off everywhere belongs in observe_rules")
	}
	host, sub, err = normHost(e.Host)
	if err != nil {
		return nil, "", false, err
	}
	if e.Path != "" && !strings.HasPrefix(e.Path, "/") {
		return nil, "", false, fmt.Errorf("path %q: it starts with /", e.Path)
	}
	r = &rule{id: e.Rule, crsID: crsID, path: e.Path}
	if e.Target != "" {
		if crsID == 0 {
			return nil, "", false, errors.New("target is for CRS rules: an spm rule matches the URL, the headers and the body as text")
		}
		if err := r.setTarget(e.Target); err != nil {
			return nil, "", false, err
		}
	}
	return r, host, sub, nil
}

func (r *rule) setTarget(t string) error {
	name, key, hasKey := strings.Cut(t, ":")
	v, err := variables.Parse(name)
	if err != nil {
		return fmt.Errorf("target %q: %w", t, err)
	}
	r.hasTgt, r.tgtVar = true, v
	if !hasKey {
		return nil
	}
	if key == "" {
		return fmt.Errorf("target %q: an empty key", t)
	}
	if len(key) > 1 && strings.HasPrefix(key, "/") && strings.HasSuffix(key, "/") {
		re, err := regexp.Compile(key[1 : len(key)-1])
		if err != nil {
			return fmt.Errorf("target %q: %w", t, err)
		}
		r.tgtKeyR = re
		return nil
	}
	// CRS matches collection keys without regard to case (ARGS, headers).
	r.tgtKey = strings.ToLower(key)
	return nil
}

// normHost lowercases a host, drops a trailing dot, and reads a leading dot
// as "and every name under it". A port, a scheme or a wildcard is an error.
func normHost(h string) (host string, sub bool, err error) {
	if h == "" {
		return "", false, nil
	}
	host = strings.TrimSuffix(strings.ToLower(h), ".")
	if strings.HasPrefix(host, ".") {
		sub, host = true, host[1:]
	}
	if host == "" || strings.ContainsAny(host, "*:/ ") {
		return "", false, fmt.Errorf("host %q: a name, or .name for the name and every name under it", h)
	}
	return host, sub, nil
}

// RequestHost is the form a request's host is matched in: lowercase, no
// port, no trailing dot.
func RequestHost(h string) string {
	h = strings.ToLower(h)
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return strings.TrimSuffix(strings.Trim(h, "[]"), ".")
}

// Inert reports whether the policy changes no single rule: no exceptions and
// nothing log-only but, at most, the whole WAF. A request under an inert
// policy takes the same path as one under none.
func (p *Policy) Inert() bool {
	return p.count == 0 && len(p.observeRules) == 0 && len(p.observeCats) == 0
}

// Mode is block or observe.
func (p *Policy) Mode() string { return p.mode }

// Observe reports whether the whole WAF only observes.
func (p *Policy) Observe() bool { return p.mode == ModeObserve }

// Exceptions is how many exceptions the policy holds.
func (p *Policy) Exceptions() int { return p.count }

// Digest is the sha256 of the file, or "empty" with no file.
func (p *Policy) Digest() string { return p.digest }

// ObserveRules and ObserveCategories are the log-only sets, sorted.
func (p *Policy) ObserveRules() []string      { return sortedKeys(p.observeRules) }
func (p *Policy) ObserveCategories() []string { return sortedKeys(p.observeCats) }

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Applied is what the policy does to one request.
type Applied struct {
	p *Policy
	// spm rules taken off this request.
	spm map[string]bool
	// CRS removals for this request's transaction.
	crs []crs.Exclusion
}

// For returns the exceptions that apply to a request for host and path.
// host is matched as RequestHost reads it.
func (p *Policy) For(host, path string) *Applied {
	a := &Applied{p: p}
	if p.count == 0 {
		return a
	}
	host = RequestHost(host)
	a.add(p.anyHost, path)
	a.add(p.exact[host], path)
	for h := host; ; {
		a.add(p.suffix[h], path)
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return a
}

func (a *Applied) add(rules []*rule, path string) {
	for _, r := range rules {
		if r.path != "" && !strings.HasPrefix(path, r.path) {
			continue
		}
		if r.crsID == 0 {
			if a.spm == nil {
				a.spm = map[string]bool{}
			}
			a.spm[r.id] = true
			continue
		}
		ex := crs.Exclusion{Rule: r.crsID}
		if r.hasTgt {
			ex.Target, ex.Variable, ex.Key, ex.KeyRx = true, r.tgtVar, r.tgtKey, r.tgtKeyR
		}
		a.crs = append(a.crs, ex)
	}
}

// Skip reports whether an spm rule is taken off this request.
func (a *Applied) Skip(ruleID string) bool { return a.spm[ruleID] }

// ObserveMatch reports whether an spm match only observes: its rule or its
// category is log-only.
func (a *Applied) ObserveMatch(ruleID, category string) bool {
	return a.p.observeRules[ruleID] || a.p.observeCats[category]
}

// CRS is what the policy asks of this request's CRS transaction.
func (a *Applied) CRS() crs.Policy {
	p := a.p
	pol := crs.Policy{Exclusions: a.crs}
	if len(p.crsObserveIDs) > 0 || len(p.crsObserveFams) > 0 {
		pol.Observe = func(id int) bool {
			if p.crsObserveIDs[id] {
				return true
			}
			if len(p.crsObserveFams) == 0 {
				return false
			}
			cats := crs.Categories([]string{strconv.Itoa(id)})
			return len(cats) == 1 && p.crsObserveFams[cats[0]]
		}
	}
	return pol
}
