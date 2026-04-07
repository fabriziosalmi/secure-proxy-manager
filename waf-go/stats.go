package main

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ── Stats Collector ─────────────────────────────────────────────────────────
// Thread-safe with minimal lock duration. Atomics for counters, lock only for maps.

type statsCollector struct {
	totalRequests    atomic.Int64
	totalBlocked     atomic.Int64
	highEntropyCount atomic.Int64

	mu             sync.Mutex
	entropySum     float64
	bodyEntropySum float64
	destCounts     map[string]int
	categoryCounts map[string]int
	uaCounts       map[string]int
	recentCount    atomic.Int64 // Approximate req/min via atomic counter
}

var stats = &statsCollector{
	destCounts:     make(map[string]int),
	categoryCounts: make(map[string]int),
	uaCounts:       make(map[string]int),
}

func (s *statsCollector) record(feature TrafficFeature, blocked bool, categories []string) {
	s.totalRequests.Add(1)
	s.recentCount.Add(1)
	if blocked {
		s.totalBlocked.Add(1)
	}
	if feature.URLEntropy > highEntropyThresh || feature.BodyEntropy > highEntropyThresh {
		s.highEntropyCount.Add(1)
	}

	// Lock only for map operations (fast path)
	s.mu.Lock()
	s.entropySum += feature.URLEntropy
	s.bodyEntropySum += feature.BodyEntropy

	host := feature.Host
	if len(s.destCounts) < 500 || s.destCounts[host] > 0 {
		s.destCounts[host]++
	}
	for _, cat := range categories {
		if len(s.categoryCounts) < 100 || s.categoryCounts[cat] > 0 {
			s.categoryCounts[cat]++
		}
	}
	ua := feature.UserAgent
	if len(ua) > 50 {
		ua = ua[:50]
	}
	if len(s.uaCounts) < 200 || s.uaCounts[ua] > 0 {
		s.uaCounts[ua]++
	}
	s.mu.Unlock()
}

// startRecentCounter resets the recent counter every 60s for req/min calculation.
func (s *statsCollector) startRecentCounter() {
	go func() {
		for {
			time.Sleep(60 * time.Second)
			s.recentCount.Store(0)
		}
	}()
}

type topEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func topN(m map[string]int, n int) []topEntry {
	entries := make([]topEntry, 0, len(m))
	for k, v := range m {
		entries = append(entries, topEntry{k, v})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Count > entries[j].Count })
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

func (s *statsCollector) reset() {
	s.totalRequests.Store(0)
	s.totalBlocked.Store(0)
	s.highEntropyCount.Store(0)
	s.recentCount.Store(0)
	s.mu.Lock()
	s.entropySum = 0
	s.bodyEntropySum = 0
	s.destCounts = make(map[string]int)
	s.categoryCounts = make(map[string]int)
	s.uaCounts = make(map[string]int)
	s.mu.Unlock()
}

func (s *statsCollector) snapshot() map[string]interface{} {
	total := s.totalRequests.Load()
	blocked := s.totalBlocked.Load()

	blockRate := 0.0
	avgURLEntropy := 0.0
	avgBodyEntropy := 0.0

	s.mu.Lock()
	if total > 0 {
		blockRate = float64(blocked) * 100 / float64(total)
		avgURLEntropy = math.Round(s.entropySum/float64(total)*100) / 100
		avgBodyEntropy = math.Round(s.bodyEntropySum/float64(total)*100) / 100
	}
	destTop := topN(s.destCounts, 10)
	catTop := topN(s.categoryCounts, 10)
	uaTop := topN(s.uaCounts, 10)
	s.mu.Unlock()

	return map[string]interface{}{
		"total_requests":         total,
		"total_blocked":          blocked,
		"block_rate_pct":         math.Round(blockRate*100) / 100,
		"avg_url_entropy":        avgURLEntropy,
		"avg_body_entropy":       avgBodyEntropy,
		"high_entropy_count":     s.highEntropyCount.Load(),
		"requests_last_minute":   s.recentCount.Load(),
		"top_destinations":       destTop,
		"top_blocked_categories": catTop,
		"top_user_agents":        uaTop,
	}
}
