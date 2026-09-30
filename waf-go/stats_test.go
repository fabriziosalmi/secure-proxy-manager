package main

import (
	"runtime"
	"testing"
	"time"
)

func TestStatsCollector(t *testing.T) {
	s := &statsCollector{
		destCounts:     make(map[string]int),
		categoryCounts: make(map[string]int),
		uaCounts:       make(map[string]int),
	}

	feat := TrafficFeature{
		Host:        "example.com",
		URLEntropy:  2.0,
		BodyEntropy: 1.0,
		UserAgent:   "Mozilla/5.0",
	}

	// Test recording
	s.record(feat, true, []string{"SQLI"})
	s.record(feat, false, []string{})

	feat2 := TrafficFeature{
		Host:       "google.com",
		URLEntropy: 5.0, // High entropy
		UserAgent:  "Curl/7.68.0",
	}
	s.record(feat2, true, []string{"XSS", "WAF"})

	snap := s.snapshot()
	if snap["total_requests"].(int64) != 3 {
		t.Errorf("Expected 3 total requests, got %v", snap["total_requests"])
	}
	if snap["total_blocked"].(int64) != 2 {
		t.Errorf("Expected 2 total blocked, got %v", snap["total_blocked"])
	}
	if snap["high_entropy_count"].(int64) != 1 {
		t.Errorf("Expected 1 high entropy, got %v", snap["high_entropy_count"])
	}

	// Test topN
	destTop := snap["top_destinations"].([]topEntry)
	if len(destTop) != 2 {
		t.Errorf("Expected 2 top destinations, got %d", len(destTop))
	}
	if destTop[0].Key != "example.com" {
		t.Errorf("Expected top destination example.com, got %s", destTop[0].Key)
	}

	// Test reset
	s.reset()
	snap = s.snapshot()
	if snap["total_requests"].(int64) != 0 {
		t.Errorf("Expected 0 after reset, got %v", snap["total_requests"])
	}
}

// The resetter must actually reset, start only once however often it is asked,
// and stop when told. The previous test only started it ("for coverage") and
// asserted nothing, so a resetter that never reset, or one started twice, passed.
func TestStatsCollector_RecentCounterResetsStartsOnceAndStops(t *testing.T) {
	s := &statsCollector{recentEvery: 20 * time.Millisecond}

	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()
	stop := s.startRecentCounter()
	s.startRecentCounter()
	s.startRecentCounter()
	if grew := runtime.NumGoroutine() - before; grew != 1 {
		t.Errorf("three calls started %d goroutines, want 1", grew)
	}

	s.recentCount.Store(5)
	deadline := time.Now().Add(2 * time.Second)
	for s.recentCount.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.recentCount.Load(); got != 0 {
		t.Errorf("the counter was not reset within the window: %d", got)
	}

	stop()
	stop() // idempotent
	time.Sleep(60 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("the resetter is still running after stop: %d goroutines, %d before", after, before)
	}
	s.recentCount.Store(7)
	time.Sleep(60 * time.Millisecond)
	if got := s.recentCount.Load(); got != 7 {
		t.Errorf("the counter was reset after stop: %d", got)
	}
}
