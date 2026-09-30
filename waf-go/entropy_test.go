package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secure-proxy-waf/internal/engine"
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
		got := engine.ShannonEntropy(c.input)
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

// SECURE-ERR-02. When the log file cannot be reopened after rotation and the
// rotated file cannot be either, the logger used to point at /dev/null: every
// later record vanished with no signal and the sink never came back. It must
// now say it is down, count what it drops, and recover when the directory
// returns.
func TestTrafficLoggerReportsAndRecoversFromALostSink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	path := filepath.Join(dir, "t.jsonl")
	tl := newTrafficLogger(path, 200)
	if tl == nil {
		t.Fatal("no logger")
	}
	tl.retryEvery = 20 * time.Millisecond
	before := trafficLogSinkDropped.Load()

	feat := TrafficFeature{ClientIP: "1.2.3.4", Method: "GET", Host: "example.com", Path: "/x"}
	// Fill the first file, then remove its directory so rotation cannot reopen
	// anything.
	tl.Write(feat)
	time.Sleep(50 * time.Millisecond)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10 && tl.Writable(); i++ {
		tl.Write(feat)
		time.Sleep(20 * time.Millisecond)
	}
	if tl.Writable() {
		t.Fatal("the logger still reports a writable sink after its directory was removed")
	}
	tl.Write(feat)
	time.Sleep(30 * time.Millisecond)
	if trafficLogSinkDropped.Load() <= before {
		t.Error("records were discarded without being counted")
	}

	// The directory returns; the next record after the retry interval recovers.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	for i := 0; i < 20 && !tl.Writable(); i++ {
		tl.Write(feat)
		time.Sleep(20 * time.Millisecond)
	}
	if !tl.Writable() {
		t.Fatal("the logger did not recover after the directory came back")
	}
	tl.Flush()
	tl.Close()
	if info, err := os.Stat(path); err != nil || info.Size() == 0 {
		t.Errorf("no record was written after recovery: %v", err)
	}
}
