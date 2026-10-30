package engine

// The regex shadow (WAF_REGEX_SHADOW=1): with it on, every rule match the
// engine in force decides is also run on the other engine, and a different
// answer is counted and logged. The verdict is always the engine in force's,
// so go with the shadow on carries no risk from re2 while showing whether it
// would have answered the same on real traffic. A request's content is never
// logged: the rule, the two answers, the input's length, whether it is valid
// UTF-8 and a prefix of its SHA-256 are.

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

var (
	shadowChecks        atomic.Uint64
	shadowDisagreements sync.Map // rule -> *atomic.Uint64

	// At most shadowLogsPerMinute log lines a minute; the counters see all.
	shadowLogMu     sync.Mutex
	shadowLogWindow time.Time
	shadowLogCount  int
)

const shadowLogsPerMinute = 20

// RecordShadow counts one comparison of rule's answer in force (inForce)
// with the other engine's (other) on input.
func RecordShadow(rule string, inForce, other bool, input string) {
	shadowChecks.Add(1)
	if inForce == other {
		return
	}
	v, _ := shadowDisagreements.LoadOrStore(rule, new(atomic.Uint64))
	v.(*atomic.Uint64).Add(1)
	if !shadowLogAllowed(time.Now()) {
		return
	}
	sum := sha256.Sum256([]byte(input))
	slog.Warn("WAF regex shadow disagrees", "rule", rule, "engine", regexEngine, "in_force", inForce, "other", other,
		"input_bytes", len(input), "valid_utf8", utf8.ValidString(input), "sha256", hex.EncodeToString(sum[:6]))
}

func shadowLogAllowed(now time.Time) bool {
	shadowLogMu.Lock()
	defer shadowLogMu.Unlock()
	if now.Sub(shadowLogWindow) >= time.Minute {
		shadowLogWindow, shadowLogCount = now, 0
	}
	shadowLogCount++
	return shadowLogCount <= shadowLogsPerMinute
}

// ShadowRuleCount is one rule's disagreements.
type ShadowRuleCount struct {
	Rule  string
	Count uint64
}

// ShadowStats are the comparisons made and the disagreements by rule,
// sorted by rule.
func ShadowStats() (checks uint64, byRule []ShadowRuleCount) {
	shadowDisagreements.Range(func(k, v any) bool {
		byRule = append(byRule, ShadowRuleCount{Rule: k.(string), Count: v.(*atomic.Uint64).Load()})
		return true
	})
	sort.Slice(byRule, func(i, j int) bool { return byRule[i].Rule < byRule[j].Rule })
	return shadowChecks.Load(), byRule
}

// SetRegexForTest sets the engine in force and the shadow, rebuilds the RE2
// forms, and returns what restores them. For tests only: the settings are
// read without a lock.
func SetRegexForTest(engineName string, shadow bool) (restore func()) {
	prevEngine, prevShadow := regexEngine, regexShadow
	regexEngine, regexShadow = engineName, shadow
	compiledRE2.Store(nil)
	buildRE2()
	return func() {
		regexEngine, regexShadow = prevEngine, prevShadow
		compiledRE2.Store(nil)
		buildRE2()
	}
}

// resetShadowForTest clears the counters.
func resetShadowForTest() {
	shadowChecks.Store(0)
	shadowDisagreements.Range(func(k, _ any) bool { shadowDisagreements.Delete(k); return true })
	shadowLogMu.Lock()
	shadowLogWindow, shadowLogCount = time.Time{}, 0
	shadowLogMu.Unlock()
}
