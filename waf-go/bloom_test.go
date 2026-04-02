package main

import (
	"testing"
	"time"
)

func TestSafeURLCache_Logic(t *testing.T) {
	c := NewSafeURLCache(10, 100*time.Millisecond)
	
	// Test hit/miss
	url := "http://example.com/safe"
	if c.IsSafe(url) {
		t.Error("Expected miss for new URL")
	}
	
	c.MarkSafe(url)
	if !c.IsSafe(url) {
		t.Error("Expected hit after MarkSafe")
	}
	
	// Test expiry
	time.Sleep(150 * time.Millisecond)
	if c.IsSafe(url) {
		t.Error("Expected miss after TTL expiry")
	}
	
	// Test maxSize and eviction
	c2 := NewSafeURLCache(5, 1*time.Hour)
	c2.MarkSafe("u1")
	c2.MarkSafe("u2")
	c2.MarkSafe("u3")
	c2.MarkSafe("u4")
	c2.MarkSafe("u5")
	c2.MarkSafe("u6") // Should trigger eviction of oldest 10% (at least 1)
	
	stats := c2.Stats()
	if stats["cache_size"] > 5 {
		t.Errorf("Cache size %d exceeds maxSize 5", stats["cache_size"])
	}
	
	// Test Invalidate
	c2.Invalidate()
	stats = c2.Stats()
	if stats["cache_size"] != 0 {
		t.Error("Cache not empty after Invalidate")
	}
}

func TestHashURL(t *testing.T) {
    h1 := hashURL("http://a.com")
    h2 := hashURL("http://a.com")
    h3 := hashURL("http://b.com")
    
    if h1 != h2 {
        t.Error("Same URL should have same hash")
    }
    if h1 == h3 {
        t.Error("Different URLs should likely have different hashes")
    }
}
