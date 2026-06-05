package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNextEventID(t *testing.T) {
	t0 := time.Now()
	a := nextEventID(t0)
	b := nextEventID(t0) // same timestamp — the atomic counter must still differ
	if a == "" || b == "" {
		t.Fatal("event id must not be empty")
	}
	if a == b {
		t.Errorf("event ids must be unique at the same timestamp: %q == %q", a, b)
	}
	// The ID rides along in the JSONL traffic record so a block can be traced.
	js, _ := json.Marshal(TrafficFeature{EventID: a, Method: "GET"})
	if !strings.Contains(string(js), `"event_id":"`+a+`"`) {
		t.Errorf("event_id missing from TrafficFeature JSON: %s", js)
	}
}

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		input    string
		expected float64
	}{
		{"", 0},
		{"aaaaa", 0},
		{"abcde", 2.32},
		{"aabbc", 1.52},
	}
	for _, c := range cases {
		got := shannonEntropy(c.input)
		if got != c.expected {
			t.Errorf("shannonEntropy(%q) = %v, expected %v", c.input, got, c.expected)
		}
	}
}

func TestTrafficLogger(t *testing.T) {
	tmpFile := "/tmp/test_traffic.jsonl"
	defer os.Remove(tmpFile)
	defer os.Remove(tmpFile + ".1")

	tl := newTrafficLogger(tmpFile, 1024) // small size to trigger rotation
	if tl == nil {
		t.Fatal("Failed to create traffic logger")
	}

	feat := TrafficFeature{
		ClientIP: "1.2.3.4",
		Method:   "GET",
		Host:     "example.com",
		Path:     "/test",
		WAFScore: 5,
	}

	// Write enough to trigger rotation
	for i := 0; i < 20; i++ {
		tl.Write(feat)
	}

	tl.Flush()
	time.Sleep(100 * time.Millisecond) // wait for drain loop

	if _, err := os.Stat(tmpFile); err != nil {
		t.Errorf("Traffic log file not created: %v", err)
	}

	tl.Close()
}
