package main

import (
	"secure-proxy-waf/internal/engine"
)

// The hybrid is the WAF's default engine (WAF_ENGINE=hybrid): CRS for the
// web signatures it measured better on, the spm engine for what CRS does not
// do. For a request the WAF can see (plain HTTP, SSL-bump) it blocks when
// the spm stages block or, after them, when CRS at paranoia 1 blocks; for
// CONNECT (HTTPS without bump) only the spm engine runs, since CRS has
// nothing to say about a host name and costs five times as much there.
// wafeval drives it through inspect.Evaluate, the code handleReqmod runs.
//
// The spm half leaves DATA_LEAK_PREVENTION, FINANCIAL_DATA and CLOUD_SECRETS
// to observe: they match and are recorded, they do not score. Example and
// dummy keys, passwords and card numbers in pasted code are
// indistinguishable from real ones. The first hybrid kept SSRF alone, judged
// on the six classes of http-attack-requests; the adversarial suite then
// showed eleven egress cases (cloud keys, webhooks, stratum, c99, XXE, ...)
// CRS does not catch.

// hybridDefaultOff are the spm categories the hybrid leaves to observe-only.
var hybridDefaultOff = []string{"DATA_LEAK_PREVENTION", "FINANCIAL_DATA", "CLOUD_SECRETS"}

// hybridEngine is spmEngine with the CRS half set.
type hybridEngine struct{ *spmEngine }

// newHybridEngine builds the hybrid with the spm categories in observe left
// to observe; keep, when not empty, switches every category off except
// those (an ablation).
func newHybridEngine(disabledHeuristics, observe, keep []string) (*hybridEngine, error) {
	var off []string
	if len(keep) > 0 {
		k := map[string]bool{}
		for _, c := range keep {
			k[c] = true
		}
		observe = nil
		for _, cr := range engine.BlockRules() {
			if !k[cr.Category] {
				off = append(off, cr.Category)
			}
		}
	}
	spm, err := newSPMEngine(disabledHeuristics, off, observe)
	if err != nil {
		return nil, err
	}
	c, err := newCorazaEngine(1)
	if err != nil {
		return nil, err
	}
	spm.crs = c.crs
	return &hybridEngine{spm}, nil
}

func (e *hybridEngine) Name() string { return "hybrid-crs-pl1-spm" }

func (e *hybridEngine) Describe() map[string]any {
	return map[string]any{"spm": e.spmEngine.Describe(), "crs": (&corazaEngine{crs: e.crs}).Describe(),
		"rule": "bump: block if the spm stages block or, after them, CRS PL1; CONNECT: the spm half only"}
}
