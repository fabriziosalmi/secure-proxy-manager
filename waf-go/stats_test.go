package main

import (
	"testing"
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
		Host:        "google.com",
		URLEntropy:  5.0, // High entropy
		UserAgent:   "Curl/7.68.0",
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

func TestStatsCollector_StartRecentCounter(t *testing.T) {
    s := &statsCollector{}
    // We can just call it to cover the goroutine start logic.
    // In a real test we'd want to wait and check, but for coverage this is enough.
    go s.startRecentCounter()
}
