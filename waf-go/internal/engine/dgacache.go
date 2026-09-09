package engine

import "time"

// dgaCacheEntry is one memoized DGA verdict.
type dgaCacheEntry struct {
	result DGAResult
	ts     time.Time
}

// AnalyzeDGACached is AnalyzeDGA with a bounded result cache: the entropy and
// bigram analysis is pure, so the same host always yields the same verdict, and
// a busy proxy sees the same hosts repeatedly.
func (e *Engine) AnalyzeDGACached(host string) DGAResult {
	e.dgaMu.RLock()
	if entry, ok := e.dgaCache[host]; ok && time.Since(entry.ts) < 10*time.Minute {
		e.dgaMu.RUnlock()
		return entry.result
	}
	e.dgaMu.RUnlock()

	result := AnalyzeDGA(host)
	e.dgaMu.Lock()
	if len(e.dgaCache) >= 10000 {
		// Evict ~10% randomly
		i := 0
		for k := range e.dgaCache {
			delete(e.dgaCache, k)
			i++
			if i >= 1000 {
				break
			}
		}
	}
	e.dgaCache[host] = dgaCacheEntry{result: result, ts: time.Now()}
	e.dgaMu.Unlock()
	return result
}
