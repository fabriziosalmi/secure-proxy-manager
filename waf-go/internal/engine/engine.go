// Package engine is the WAF's detection core: the rule set, the pre-filter, the
// behavioural heuristics, and the caches and thresholds that decide whether a
// request is refused.
//
// It is a package because it used not to be. The WAF was eleven files and
// 3,786 lines in a flat package main, so every file could read and write the
// state behind the block decision — including blockThreshold, which a test
// assigned at package scope and never restored, making the effective threshold
// for every later test a function of file ordering (SECURE-ARCH-03). The
// backend in the same repository has kept twelve internal packages and an
// acyclic import graph throughout; the component that parses attacker-supplied
// bodies now holds the same line.
//
// The mutable state lives on an Engine value, constructed by the caller. Nothing
// outside this package can assign to it: package main is the ICAP transport and
// the composition root, and reaches the decision only through these methods.
package engine

import (
	"sort"
	"sync"
	"time"
)

// Config is what the composition root supplies. A zero BlockThreshold,
// SafeCacheSize or SafeCacheTTL takes the default rather than disabling the
// feature, so a partially-filled Config cannot silently produce an engine that
// blocks everything or caches nothing.
type Config struct {
	BlockThreshold     int
	DisabledCategories []string
	Heuristics         HeuristicConfig
	SafeCacheSize      int
	SafeCacheTTL       time.Duration
}

const (
	defaultBlockThreshold = 10
	defaultSafeCacheSize  = 50000
	defaultSafeCacheTTL   = 5 * time.Minute
)

// Engine holds the detection state for one WAF instance.
type Engine struct {
	// blockThreshold is fixed at construction: the score at or above which a
	// request is refused. It is deliberately not settable — an engine whose
	// verdict can be moved at runtime cannot be reasoned about from a log line.
	blockThreshold int

	disabledMu sync.RWMutex
	disabled   map[string]bool

	heurMu sync.RWMutex
	heur   HeuristicConfig

	// clientStates is the heuristics' per-IP history (beaconing, sharding,
	// sequence). Bounded in getClientStateLocked and swept by CleanupClientStates.
	csMu         sync.Mutex
	clientStates map[string]*clientState

	// dgaCache memoizes the DGA verdict per host: 10K domains, 10 min TTL.
	dgaMu    sync.RWMutex
	dgaCache map[string]dgaCacheEntry

	safeCache *SafeURLCache
}

// New builds an engine from cfg. The safe-URL cache starts its own eviction
// goroutine, so an engine is meant to live as long as the process.
func New(cfg Config) *Engine {
	threshold := cfg.BlockThreshold
	if threshold <= 0 {
		threshold = defaultBlockThreshold
	}
	size := cfg.SafeCacheSize
	if size <= 0 {
		size = defaultSafeCacheSize
	}
	ttl := cfg.SafeCacheTTL
	if ttl <= 0 {
		ttl = defaultSafeCacheTTL
	}
	e := &Engine{
		blockThreshold: threshold,
		disabled:       make(map[string]bool, len(cfg.DisabledCategories)),
		heur:           cfg.Heuristics,
		clientStates:   make(map[string]*clientState),
		dgaCache:       make(map[string]dgaCacheEntry, 10000),
		safeCache:      NewSafeURLCache(size, ttl),
	}
	for _, cat := range cfg.DisabledCategories {
		if cat != "" {
			e.disabled[cat] = true
		}
	}
	return e
}

// BlockThreshold is the score at or above which a request is refused.
func (e *Engine) BlockThreshold() int { return e.blockThreshold }

// Blocked reports whether an anomaly score is enough to refuse the request.
// Every block decision in the WAF goes through this one comparison.
func (e *Engine) Blocked(score int) bool { return score >= e.blockThreshold }

// CategoryEnabled reports whether a rule category is currently active.
func (e *Engine) CategoryEnabled(cat string) bool {
	e.disabledMu.RLock()
	defer e.disabledMu.RUnlock()
	return !e.disabled[cat]
}

// SetCategoryEnabled turns a rule category on or off at runtime.
func (e *Engine) SetCategoryEnabled(cat string, enabled bool) {
	e.disabledMu.Lock()
	defer e.disabledMu.Unlock()
	if enabled {
		delete(e.disabled, cat)
		return
	}
	e.disabled[cat] = true
}

// DisabledCategories returns the disabled set, sorted, so a caller that folds it
// into a digest (the ISTag) gets the same value for the same configuration.
func (e *Engine) DisabledCategories() []string {
	e.disabledMu.RLock()
	defer e.disabledMu.RUnlock()
	cats := make([]string, 0, len(e.disabled))
	for cat := range e.disabled {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	return cats
}

// DisabledCategoryCount is the size of that set, for /metrics.
func (e *Engine) DisabledCategoryCount() int {
	e.disabledMu.RLock()
	defer e.disabledMu.RUnlock()
	return len(e.disabled)
}

// SafeCache is the URL cache of inputs already scanned clean.
func (e *Engine) SafeCache() *SafeURLCache { return e.safeCache }
