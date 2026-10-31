package main

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"secure-proxy-waf/internal/policy"
)

// Report is the whole measurement. Every map is keyed by strings, which
// encoding/json writes in sorted order, and every slice is sorted before it
// is written, so the same inputs give the same bytes.
type Report struct {
	Tool    map[string]string `json:"tool"`
	Engine  map[string]any    `json:"engine"`
	Corpus  []CorpusFile      `json:"corpus"`
	Summary []Cell            `json:"summary"`
	ByCat   []Cell            `json:"by_category"`
	// FPRules: for benign records that were blocked, how often each rule
	// contributed, per source and context. These are the rules to look at.
	FPRules map[string]map[string]int `json:"fp_rules"`
	// TPRules: for attacks that were blocked, how often each rule
	// contributed, per source and context: what the detection rests on.
	TPRules map[string]map[string]int `json:"tp_rules"`
	// FNObserved: attack records that scored above zero but stayed under the
	// threshold, per source and context: misses that were close.
	FNObserved map[string]int `json:"fn_observed"`
	// Signals: per source, context and label, on how many records each
	// detector scored, blocked or not; SignalRecords is how many records
	// were inspected there (parse errors and LAN hosts left out). A detector
	// scoring under the threshold is a signal too, so this is what each one
	// sees in each context, on attacks and on benign traffic.
	Signals       map[string]map[string]int `json:"signals"`
	SignalRecords map[string]int            `json:"signal_records"`
	// Examples: up to three record IDs per false positive and false
	// negative cell, so a result can be traced back to its data. IDs only.
	Examples map[string][]string    `json:"examples"`
	Latency  map[string]LatencyStat `json:"latency,omitempty"`
	// FPExplain: with -explain N, the first N false positives per source and
	// context, with what each rule matched.
	FPExplain map[string][]FPCase `json:"fp_explain,omitempty"`
	explainN  int
	// LatencyBySource is the same, per source and context.
	LatencyBySource map[string]LatencyStat `json:"latency_by_source,omitempty"`
	// CRSScore checks, on every request CRS scored, that its anomaly score is
	// the sum of each scoring rule's severity weight per matched variable:
	// what taking an observed rule's share off rests on.
	CRSScore *ScoreCheck `json:"crs_score_check,omitempty"`

	// emitted are the exceptions -emit-exceptions writes, keyed so each is
	// written once; emitSources limits them to some sources (all if empty).
	emitted     map[string]policy.Exception
	emitSources map[string]bool

	cells      map[string]*Cell
	catCells   map[string]*Cell
	latency    map[string][]time.Duration
	keepTiming bool
}

type ScoreCheck struct {
	Checked  int      `json:"checked"`
	Mismatch int      `json:"mismatch"`
	Examples []string `json:"examples,omitempty"`
}

type FPCase struct {
	ID    string   `json:"id"`
	Rules []string `json:"rules"`
}

type CorpusFile struct {
	File    string `json:"file"`
	Records int    `json:"records"`
	SHA256  string `json:"sha256,omitempty"`
}

// Cell counts one source x context (or source x context x category).
type Cell struct {
	Source      string `json:"source"`
	Context     string `json:"context"`
	Category    string `json:"category,omitempty"`
	TP          int    `json:"tp"`
	FN          int    `json:"fn"`
	FP          int    `json:"fp"`
	TN          int    `json:"tn"`
	ParseErrors int    `json:"parse_errors"`
	LANSkipped  int    `json:"lan_skipped"`
	// Uninspectable: compressed responses the rules could not read.
	// NotInspected: responses the engine does not inspect at all.
	Uninspectable int     `json:"uninspectable,omitempty"`
	NotInspected  int     `json:"not_inspected,omitempty"`
	TPR           float64 `json:"tpr"`
	FPR           float64 `json:"fpr"`
}

type LatencyStat struct {
	N     int     `json:"n"`
	P50us float64 `json:"p50_us"`
	P90us float64 `json:"p90_us"`
	P99us float64 `json:"p99_us"`
	MaxUs float64 `json:"max_us"`
}

func newReport(eng Engine, commit string, keepTiming bool) *Report {
	return &Report{
		Tool:          map[string]string{"go": runtime.Version(), "commit": commit, "engine": eng.Name()},
		Engine:        eng.Describe(),
		FPRules:       map[string]map[string]int{},
		TPRules:       map[string]map[string]int{},
		FNObserved:    map[string]int{},
		Signals:       map[string]map[string]int{},
		Examples:      map[string][]string{},
		SignalRecords: map[string]int{},
		cells:         map[string]*Cell{},
		catCells:      map[string]*Cell{},
		latency:       map[string][]time.Duration{},
		keepTiming:    keepTiming,
	}
}

func (rep *Report) cell(m map[string]*Cell, src, ctx, cat string) *Cell {
	k := src + "|" + ctx + "|" + cat
	c, ok := m[k]
	if !ok {
		c = &Cell{Source: src, Context: ctx, Category: cat}
		m[k] = c
	}
	return c
}

func (rep *Report) example(key, id string) {
	if len(rep.Examples[key]) < 3 {
		rep.Examples[key] = append(rep.Examples[key], id)
	}
}

func (rep *Report) add(rec *Record, eng Engine, clientIP string) {
	sum := rep.cell(rep.cells, rec.Source, rec.Context, "")
	cat := rep.cell(rep.catCells, rec.Source, rec.Context, rec.Category)
	key := rec.Source + "|" + rec.Context

	var v Verdict
	var start time.Time
	if rec.Kind == "response" {
		resp, err := buildResponse(rec)
		if err != nil {
			sum.ParseErrors++
			cat.ParseErrors++
			rep.example("parse_error|"+key, rec.ID)
			return
		}
		start = now()
		v = eng.InspectResponse(resp)
		if v.Uninspectable {
			sum.Uninspectable++
			cat.Uninspectable++
		}
		if v.NotInspected {
			sum.NotInspected++
			cat.NotInspected++
		}
	} else {
		r, err := buildRequest(rec)
		if err != nil {
			sum.ParseErrors++
			cat.ParseErrors++
			rep.example("parse_error|"+key, rec.ID)
			return
		}
		start = now()
		v = eng.Inspect(r, clientIP)
	}
	if rep.keepTiming {
		d := now().Sub(start)
		rep.latency[rec.Context] = append(rep.latency[rec.Context], d)
		rep.latency[key] = append(rep.latency[key], d)
	}
	if v.LANSkipped {
		sum.LANSkipped++
		cat.LANSkipped++
	}
	if v.crsRan && v.crsInbound > 0 {
		if rep.CRSScore == nil {
			rep.CRSScore = &ScoreCheck{}
		}
		rep.CRSScore.Checked++
		total := 0
		for _, w := range v.crsContrib {
			total += w
		}
		if total != v.crsInbound {
			rep.CRSScore.Mismatch++
			if len(rep.CRSScore.Examples) < 20 {
				rep.CRSScore.Examples = append(rep.CRSScore.Examples, fmt.Sprintf("%s: inbound %d, sum %d %v", rec.ID, v.crsInbound, total, v.crsContrib))
			}
		}
	}

	if !v.LANSkipped {
		sk := key + "|" + rec.Label
		rep.SignalRecords[sk]++
		for _, d := range v.Signals {
			m := rep.Signals[sk]
			if m == nil {
				m = map[string]int{}
				rep.Signals[sk] = m
			}
			m[d]++
		}
	}

	attack := rec.Label == "attack"
	for _, c := range []*Cell{sum, cat} {
		switch {
		case attack && v.Blocked:
			c.TP++
		case attack:
			c.FN++
		case v.Blocked:
			c.FP++
		default:
			c.TN++
		}
	}
	if attack && v.Blocked {
		m := rep.TPRules[key]
		if m == nil {
			m = map[string]int{}
			rep.TPRules[key] = m
		}
		for _, id := range v.Rules {
			m[id]++
		}
	}
	switch {
	case attack && !v.Blocked:
		rep.example("fn|"+key+"|"+rec.Category, rec.ID)
		if v.Score > 0 {
			rep.FNObserved[key]++
		}
	case !attack && v.Blocked:
		rep.emit(rec.Source, v.exceptions, rec.ID)
		rep.example("fp|"+key+"|"+rec.Category, rec.ID)
		m := rep.FPRules[key]
		if m == nil {
			m = map[string]int{}
			rep.FPRules[key] = m
		}
		for _, id := range v.Rules {
			m[id]++
		}
		if rep.explainN > 0 && len(rep.FPExplain[key]) < rep.explainN {
			if rep.FPExplain == nil {
				rep.FPExplain = map[string][]FPCase{}
			}
			rep.FPExplain[key] = append(rep.FPExplain[key], FPCase{ID: rec.ID, Rules: v.Explain})
		}
	}
}

// emit records the exceptions of one false positive.
func (rep *Report) emit(source string, ex []policy.Exception, id string) {
	if rep.emitted == nil || len(rep.emitSources) > 0 && !rep.emitSources[source] {
		return
	}
	for _, e := range ex {
		k := e.Rule + "|" + e.Host + "|" + e.Target
		if _, ok := rep.emitted[k]; !ok {
			e.Comment = "wafeval false positive " + id
			rep.emitted[k] = e
		}
	}
}

// policyFile is the emitted exceptions as a policy document, sorted.
func (rep *Report) policyFile() policy.File {
	keys := make([]string, 0, len(rep.emitted))
	for k := range rep.emitted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	f := policy.File{Version: 1}
	for _, k := range keys {
		f.Exceptions = append(f.Exceptions, rep.emitted[k])
	}
	return f
}

func rate(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(int(float64(num)/float64(den)*1e6+0.5)) / 1e6
}

func (rep *Report) finish() {
	collect := func(m map[string]*Cell) []Cell {
		out := make([]Cell, 0, len(m))
		for _, c := range m {
			c.TPR = rate(c.TP, c.TP+c.FN)
			c.FPR = rate(c.FP, c.FP+c.TN)
			out = append(out, *c)
		}
		sort.Slice(out, func(i, j int) bool {
			a, b := out[i], out[j]
			if a.Source != b.Source {
				return a.Source < b.Source
			}
			if a.Context != b.Context {
				return a.Context < b.Context
			}
			return a.Category < b.Category
		})
		return out
	}
	rep.Summary = collect(rep.cells)
	rep.ByCat = collect(rep.catCells)
	sort.Slice(rep.Corpus, func(i, j int) bool { return rep.Corpus[i].File < rep.Corpus[j].File })
	if rep.keepTiming {
		rep.Latency = map[string]LatencyStat{}
		rep.LatencyBySource = map[string]LatencyStat{}
		for ctx, ds := range rep.latency {
			sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
			q := func(p float64) float64 {
				i := int(p*float64(len(ds)-1) + 0.5)
				return float64(ds[i].Nanoseconds()) / 1000
			}
			st := LatencyStat{N: len(ds), P50us: q(0.50), P90us: q(0.90), P99us: q(0.99), MaxUs: q(1)}
			if strings.Contains(ctx, "|") {
				rep.LatencyBySource[ctx] = st
			} else {
				rep.Latency[ctx] = st
			}
		}
	}
}

func (rep *Report) markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# wafeval: %s at %s\n\n", rep.Tool["engine"], rep.Tool["commit"])
	b.WriteString("| Source | Context | TP | FN | FP | TN | TPR | FPR | Parse errors | LAN skipped |\n|---|---|---|---|---|---|---|---|---|---|\n")
	for _, c := range rep.Summary {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %.4f | %.4f | %d | %d |\n",
			c.Source, c.Context, c.TP, c.FN, c.FP, c.TN, c.TPR, c.FPR, c.ParseErrors, c.LANSkipped)
	}
	b.WriteString("\n## By category\n\n| Source | Context | Category | TP | FN | FP | TN | TPR | FPR |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, c := range rep.ByCat {
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %d | %.4f | %.4f |\n",
			c.Source, c.Context, c.Category, c.TP, c.FN, c.FP, c.TN, c.TPR, c.FPR)
	}
	b.WriteString("\n## Rules behind false positives\n\n")
	keys := make([]string, 0, len(rep.FPRules))
	for k := range rep.FPRules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		type kv struct {
			id string
			n  int
		}
		var rs []kv
		for id, n := range rep.FPRules[k] {
			rs = append(rs, kv{id, n})
		}
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].n != rs[j].n {
				return rs[i].n > rs[j].n
			}
			return rs[i].id < rs[j].id
		})
		fmt.Fprintf(&b, "- %s:", k)
		for i, r := range rs {
			if i == 10 {
				break
			}
			fmt.Fprintf(&b, " %s %d,", r.id, r.n)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n## Detector signals (records where the detector scored, blocked or not)\n\n")
	skeys := make([]string, 0, len(rep.SignalRecords))
	for k := range rep.SignalRecords {
		skeys = append(skeys, k)
	}
	sort.Strings(skeys)
	for _, k := range skeys {
		n := rep.SignalRecords[k]
		ds := make([]string, 0, len(rep.Signals[k]))
		for d := range rep.Signals[k] {
			ds = append(ds, d)
		}
		sort.Strings(ds)
		fmt.Fprintf(&b, "- %s (%d records):", k, n)
		for _, d := range ds {
			fmt.Fprintf(&b, " %s %d (%.4f),", d, rep.Signals[k][d], rate(rep.Signals[k][d], n))
		}
		b.WriteString("\n")
	}
	if rep.Latency != nil {
		b.WriteString("\n## In-process latency (scan + heuristics), microseconds\n\n| Context | N | p50 | p90 | p99 | max |\n|---|---|---|---|---|---|\n")
		ctxs := make([]string, 0, len(rep.Latency))
		for c := range rep.Latency {
			ctxs = append(ctxs, c)
		}
		sort.Strings(ctxs)
		for _, c := range ctxs {
			l := rep.Latency[c]
			fmt.Fprintf(&b, "| %s | %d | %.1f | %.1f | %.1f | %.1f |\n", c, l.N, l.P50us, l.P90us, l.P99us, l.MaxUs)
		}
		keys := make([]string, 0, len(rep.LatencyBySource))
		for k := range rep.LatencyBySource {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			l := rep.LatencyBySource[k]
			fmt.Fprintf(&b, "| %s | %d | %.1f | %.1f | %.1f | %.1f |\n", k, l.N, l.P50us, l.P90us, l.P99us, l.MaxUs)
		}
	}
	return b.String()
}
