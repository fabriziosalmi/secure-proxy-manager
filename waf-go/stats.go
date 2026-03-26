package main

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ── Stats Collector ─────────────────────────────────────────────────────────

type statsCollector struct {
	mu                sync.Mutex
	totalRequests     int64
	totalBlocked      int64
	entropySum        float64
	bodyEntropySum    float64
	highEntropyCount  int64
	destCounts        map[string]int
	categoryCounts    map[string]int
	uaCounts          map[string]int
	recentTimestamps  []time.Time // last 60s window for req/min
}

var stats = &statsCollector{
	destCounts:     make(map[string]int),
	categoryCounts: make(map[string]int),
	uaCounts:       make(map[string]int),
}

func (s *statsCollector) record(feature TrafficFeature, blocked bool, categories []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	atomic.AddInt64(&s.totalRequests, 1)
	if blocked {
		atomic.AddInt64(&s.totalBlocked, 1)
	}

	s.entropySum += feature.URLEntropy
	s.bodyEntropySum += feature.BodyEntropy
	if feature.URLEntropy > highEntropyThresh || feature.BodyEntropy > highEntropyThresh {
		s.highEntropyCount++
	}

	// Top destinations (cap at 500)
	if len(s.destCounts) < 500 {
		s.destCounts[feature.Host]++
	} else if _, ok := s.destCounts[feature.Host]; ok {
		s.destCounts[feature.Host]++
	}

	for _, cat := range categories {
		s.categoryCounts[cat]++
	}

	// Shorten UA for grouping
	ua := feature.UserAgent
	if len(ua) > 50 {
		ua = ua[:50]
	}
	if len(s.uaCounts) < 200 {
		s.uaCounts[ua]++
	} else if _, ok := s.uaCounts[ua]; ok {
		s.uaCounts[ua]++
	}

	now := time.Now()
	s.recentTimestamps = append(s.recentTimestamps, now)
	// Trim to last 60s
	cutoff := now.Add(-60 * time.Second)
	i := 0
	for i < len(s.recentTimestamps) && s.recentTimestamps[i].Before(cutoff) {
		i++
	}
	s.recentTimestamps = s.recentTimestamps[i:]
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

func (s *statsCollector) snapshot() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := atomic.LoadInt64(&s.totalRequests)
	blocked := atomic.LoadInt64(&s.totalBlocked)

	blockRate := 0.0
	avgURLEntropy := 0.0
	avgBodyEntropy := 0.0
	if total > 0 {
		blockRate = float64(blocked) * 100 / float64(total)
		avgURLEntropy = math.Round(s.entropySum/float64(total)*100) / 100
		avgBodyEntropy = math.Round(s.bodyEntropySum/float64(total)*100) / 100
	}

	return map[string]interface{}{
		"total_requests":        total,
		"total_blocked":         blocked,
		"block_rate_pct":        math.Round(blockRate*100) / 100,
		"avg_url_entropy":       avgURLEntropy,
		"avg_body_entropy":      avgBodyEntropy,
		"high_entropy_count":    s.highEntropyCount,
		"requests_last_minute":  len(s.recentTimestamps),
		"top_destinations":      topN(s.destCounts, 10),
		"top_blocked_categories": topN(s.categoryCounts, 10),
		"top_user_agents":       topN(s.uaCounts, 10),
	}
}
