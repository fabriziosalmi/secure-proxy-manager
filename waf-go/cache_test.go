package main

import (
	"testing"
	"time"
)

func TestSafeURLCache(t *testing.T) {
	c := NewSafeURLCache(100, 100*time.Millisecond)
	c.MarkSafe("http://test.com")
	if !c.IsSafe("http://test.com") {
		t.Errorf("Expected http://test.com to be safe")
	}
	if c.IsSafe("http://other.com") {
		t.Errorf("Expected http://other.com not to be safe")
	}

	stats := c.Stats()
	if stats["cache_size"] != 1 {
		t.Errorf("Expected cache size 1")
	}

	c.MarkSafe("http://abc.com")
	c.Invalidate()
	stats = c.Stats()
	if stats["cache_size"] != 0 {
		t.Errorf("Expected cache size 0 after Invalidate")
	}
}
