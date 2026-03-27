package main

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// SafeURLCache is a concurrent-safe cache of URL hashes that have been
// scanned and found clean. URLs in this cache skip the expensive regex
// scan on subsequent requests. The cache auto-expires entries after TTL.
//
// This is NOT a true Bloom filter (no false positives by design) — it's
// a bounded hash set with TTL eviction. Simpler, deterministic, and
// sufficient for our use case.
type SafeURLCache struct {
	mu       sync.RWMutex
	entries  map[uint64]time.Time // hash → last seen
	maxSize  int
	ttl      time.Duration
	hits     atomic.Int64
	misses   atomic.Int64
	evictions atomic.Int64
}

func NewSafeURLCache(maxSize int, ttl time.Duration) *SafeURLCache {
	c := &SafeURLCache{
		entries: make(map[uint64]time.Time, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
	go c.evictLoop()
	return c
}

// hashURL returns a fast 64-bit hash of the URL.
func hashURL(url string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(url)) //nolint:errcheck
	return h.Sum64()
}

// IsSafe returns true if the URL has been previously scanned and found clean.
func (c *SafeURLCache) IsSafe(url string) bool {
	h := hashURL(url)
	c.mu.RLock()
	ts, ok := c.entries[h]
	c.mu.RUnlock()
	if ok && time.Since(ts) < c.ttl {
		c.hits.Add(1)
		return true
	}
	c.misses.Add(1)
	return false
}

// MarkSafe adds a URL to the safe cache after it passed WAF scanning.
func (c *SafeURLCache) MarkSafe(url string) {
	h := hashURL(url)
	c.mu.Lock()
	if len(c.entries) >= c.maxSize {
		// Evict oldest 10%
		c.evictOldestLocked(c.maxSize / 10)
	}
	c.entries[h] = time.Now()
	c.mu.Unlock()
}

// Invalidate removes a URL from the safe cache (e.g., when rules change).
func (c *SafeURLCache) Invalidate() {
	c.mu.Lock()
	c.entries = make(map[uint64]time.Time, c.maxSize)
	c.mu.Unlock()
}

// Stats returns cache hit/miss/size statistics.
func (c *SafeURLCache) Stats() map[string]int64 {
	c.mu.RLock()
	size := int64(len(c.entries))
	c.mu.RUnlock()
	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses
	var hitRate int64
	if total > 0 {
		hitRate = (hits * 100) / total
	}
	return map[string]int64{
		"cache_size":     size,
		"cache_hits":     hits,
		"cache_misses":   misses,
		"cache_hit_rate": hitRate,
		"cache_evictions": c.evictions.Load(),
	}
}

func (c *SafeURLCache) evictOldestLocked(count int) {
	if count <= 0 {
		return
	}
	// Simple: remove entries with oldest timestamps
	type entry struct {
		hash uint64
		ts   time.Time
	}
	var oldest []entry
	for h, ts := range c.entries {
		oldest = append(oldest, entry{h, ts})
		if len(oldest) > count*2 {
			break // Don't iterate the whole map for large caches
		}
	}
	// Sort by time (simple selection for small count)
	for i := 0; i < count && i < len(oldest); i++ {
		minIdx := i
		for j := i + 1; j < len(oldest); j++ {
			if oldest[j].ts.Before(oldest[minIdx].ts) {
				minIdx = j
			}
		}
		oldest[i], oldest[minIdx] = oldest[minIdx], oldest[i]
		delete(c.entries, oldest[i].hash)
		c.evictions.Add(1)
	}
}

func (c *SafeURLCache) evictLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for h, ts := range c.entries {
			if now.Sub(ts) > c.ttl {
				delete(c.entries, h)
				c.evictions.Add(1)
			}
		}
		c.mu.Unlock()
	}
}
