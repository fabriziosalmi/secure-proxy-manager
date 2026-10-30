// Command wafeval measures a WAF engine against labelled corpora: true and
// false positives per source, context (bump, nobump) and category, the rules
// behind the false positives, and the in-process latency.
//
// It is a measurement tool, not part of the product. Detection results are
// deterministic: two runs on the same commit and corpus give the same report
// (-no-latency leaves out the only part that varies).
//
//	wafeval -out report.json [-md report.md] corpus/*.jsonl
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/pprof"
	"strings"
	"time"

	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/policy"
)

// Record is one corpus line; see corpus/convert.py for the schema.
type Record struct {
	ID       string     `json:"id"`
	Source   string     `json:"source"`
	Label    string     `json:"label"`
	Category string     `json:"category"`
	Context  string     `json:"context"`
	Method   string     `json:"method"`
	URL      string     `json:"url"`
	Headers  [][]string `json:"headers"`
	Body     string     `json:"body"`
	// Kind is "request" (the default) or "response"; a response record
	// carries Status, and its Headers and Body are the response's.
	Kind   string `json:"kind,omitempty"`
	Status int    `json:"status,omitempty"`
}

func main() {
	out := flag.String("out", "", "write the JSON report here (required)")
	md := flag.String("md", "", "also write a Markdown summary here")
	noLatency := flag.Bool("no-latency", false, "leave latency out of the report, so two runs can be compared byte for byte")
	commit := flag.String("commit", "", "commit of the code under measurement, recorded in the report")
	heurOff := flag.String("heuristics-off", "waf_h_sequence", "comma-separated heuristics to switch off; the default is the state the backend pushes with default settings")
	catsOff := flag.String("categories-off", "", "comma-separated categories to switch off")
	limit := flag.Int("limit", 0, "read at most this many records per corpus file (0: all)")
	cpuProfile := flag.String("cpuprofile", "", "write a CPU profile of the run here")
	explainN := flag.Int("explain", 0, "for the first N false positives per source and context, record what each rule matched")
	keepPolicy := flag.Bool("crs-keep-policy", false, "ablation: apply none of the CRS policy removals and exclusions")
	restore := flag.String("crs-restore", "", "ablation: comma-separated CRS rule IDs to keep although the adapter removes them")
	observe := flag.String("hybrid-observe", strings.Join(hybridDefaultOff, ","), "spm categories the hybrid and spm-observe leave to observe")
	engineName := flag.String("engine", "spm", "engine under measurement: spm, spm-observe, coraza-pl1, coraza-pl2, hybrid, hybrid-ssrf")
	policyFile := flag.String("policy", "", "apply this WAF policy file (WAF_POLICY_FILE) to the spm and hybrid engines")
	emitFile := flag.String("emit-exceptions", "", "write a policy file with one exception per rule that scored on a false positive")
	emitSources := flag.String("emit-sources", "", "comma-separated sources whose false positives -emit-exceptions takes (all if empty)")
	flag.Parse()
	if *out == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: wafeval -out report.json [-md report.md] corpus.jsonl...")
		os.Exit(2)
	}

	crsOptions.KeepPolicy = *keepPolicy
	crsOptions.Restore = map[string]bool{}
	for _, id := range splitList(*restore) {
		crsOptions.Restore[id] = true
	}
	observeOff := splitList(*observe)
	var eng Engine
	var err error
	switch *engineName {
	case "spm":
		eng, err = newSPMEngine(splitList(*heurOff), splitList(*catsOff), nil)
	case "coraza-pl1":
		eng, err = newCorazaEngine(1)
	case "coraza-pl2":
		eng, err = newCorazaEngine(2)
	case "spm-observe":
		// The spm engine with DLP and FIN observe-only, the reference the
		// hybrid must not fall below (gate A2 in gates.py).
		eng, err = newSPMEngine(splitList(*heurOff), nil, observeOff)
	case "hybrid":
		eng, err = newHybridEngine(splitList(*heurOff), observeOff, nil)
	case "hybrid-ssrf":
		eng, err = newHybridEngine(splitList(*heurOff), nil, []string{"SSRF"})
	default:
		err = fmt.Errorf("unknown engine %q", *engineName)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wafeval:", err)
		os.Exit(2)
	}
	// After the engine: the policy checks spm rule IDs against the loaded
	// rules, custom rules included.
	if *policyFile != "" {
		if evalPolicy, err = policy.Load(*policyFile, engine.KnownRuleID); err != nil {
			fmt.Fprintln(os.Stderr, "wafeval:", err)
			os.Exit(2)
		}
	}

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wafeval:", err)
			os.Exit(2)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintln(os.Stderr, "wafeval:", err)
			os.Exit(2)
		}
		defer f.Close()
	}

	rep := newReport(eng, *commit, !*noLatency)
	rep.explainN = *explainN
	explainOn = *explainN > 0
	if evalPolicy != nil {
		rep.Tool["policy_sha256"] = evalPolicy.Digest()
		rep.Tool["policy_exceptions"] = fmt.Sprint(evalPolicy.Exceptions())
	}
	if *emitFile != "" {
		// The CRS targets come from the explain data.
		emitOn, explainOn = true, true
		rep.emitted = map[string]policy.Exception{}
		rep.emitSources = map[string]bool{}
		for _, s := range splitList(*emitSources) {
			rep.emitSources[s] = true
		}
	}
	seq := 0
	for _, path := range flag.Args() {
		if err := runFile(path, eng, rep, &seq, *limit); err != nil {
			fmt.Fprintln(os.Stderr, "wafeval:", err)
			os.Exit(1)
		}
	}
	rep.finish()
	pprof.StopCPUProfile()

	if err := writeJSON(*out, rep); err != nil {
		fmt.Fprintln(os.Stderr, "wafeval:", err)
		os.Exit(1)
	}
	if *emitFile != "" {
		if err := writeJSON(*emitFile, rep.policyFile()); err != nil {
			fmt.Fprintln(os.Stderr, "wafeval:", err)
			os.Exit(1)
		}
	}
	if *md != "" {
		if err := os.WriteFile(*md, []byte(rep.markdown()), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "wafeval:", err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stderr, "wafeval: %d records, report in %s\n", seq, *out)
}

func runFile(path string, eng Engine, rep *Report, seq *int, limit int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	sc := bufio.NewScanner(io.TeeReader(f, h))
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	n := 0
	for sc.Scan() {
		if limit > 0 && n >= limit {
			break
		}
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return fmt.Errorf("%s line %d: %w", path, n+1, err)
		}
		n++
		*seq++
		rep.add(&rec, eng, clientIPFor(*seq))
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	digest := ""
	if limit == 0 {
		digest = hex.EncodeToString(h.Sum(nil))
	}
	rep.Corpus = append(rep.Corpus, CorpusFile{File: path, Records: n, SHA256: digest})
	return nil
}

// clientIPFor gives every record its own client address, in 100.64.0.0/10,
// so the per-client heuristic windows never mix two records.
func clientIPFor(seq int) string {
	return fmt.Sprintf("100.%d.%d.%d", 64+(seq>>16)&63, (seq>>8)&255, seq&255)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// now is replaced in tests.
var now = time.Now
