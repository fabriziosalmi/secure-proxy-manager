package main

import (
	"bufio"
	"encoding/json"
	"log"
	"math"
	"os"
	"path/filepath"
	"sync"
)

const (
	trafficLogPath     = "/data/waf_traffic.jsonl"
	trafficLogMaxBytes = 100 * 1 << 20 // 100 MB
	highEntropyThresh  = 4.5
	logQueueSize       = 4096 // Bounded channel — drops on overflow
)

// ── Shannon Entropy ─────────────────────────────────────────────────────────

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return math.Round(entropy*100) / 100
}

// ── Traffic Feature Extraction ──────────────────────────────────────────────

type TrafficFeature struct {
	Timestamp       string   `json:"ts"`
	ClientIP        string   `json:"client_ip"`
	Method          string   `json:"method"`
	Host            string   `json:"host"`
	Path            string   `json:"path"`
	URLLength       int      `json:"url_length"`
	URLEntropy      float64  `json:"url_entropy"`
	QueryParamCount int      `json:"query_param_count"`
	BodySize        int      `json:"body_size"`
	BodyEntropy     float64  `json:"body_entropy"`
	ContentType     string   `json:"content_type"`
	HeaderCount     int      `json:"header_count"`
	UserAgent       string   `json:"user_agent"`
	IsTLS           bool     `json:"is_tls"`
	DestPort        string   `json:"dest_port"`
	WAFScore        int      `json:"waf_score"`
	WAFRules        []string `json:"waf_rules"`
	Action          string   `json:"action"`
	LatencyUS       int64    `json:"latency_us"`
}

// ── Async JSONL Traffic Logger ──────────────────────────────────────────────
// Uses a bounded channel to decouple request handling from disk I/O.
// If the channel is full, new entries are silently dropped (backpressure).

type TrafficLogger struct {
	ch      chan TrafficFeature
	mu      sync.Mutex // Protects file ops only during rotation
	writer  *bufio.Writer
	file    *os.File
	path    string
	maxSize int64
	written int64
	done    chan struct{}
}

var trafficLog *TrafficLogger

func newTrafficLogger(path string, maxSize int64) *TrafficLogger {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("Failed to create traffic log dir %s: %v\n", dir, err)
		return nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open traffic log %s: %v\n", path, err)
		return nil
	}

	info, _ := f.Stat()
	written := int64(0)
	if info != nil {
		written = info.Size()
	}

	tl := &TrafficLogger{
		ch:      make(chan TrafficFeature, logQueueSize),
		writer:  bufio.NewWriterSize(f, 64*1024),
		file:    f,
		path:    path,
		maxSize: maxSize,
		written: written,
		done:    make(chan struct{}),
	}

	// Single writer goroutine — no lock contention on hot path
	go tl.drainLoop()

	return tl
}

// Write enqueues a feature for async writing. Non-blocking; drops if full.
func (tl *TrafficLogger) Write(feature TrafficFeature) {
	if tl == nil {
		return
	}
	select {
	case tl.ch <- feature:
	default:
		// Queue full — drop silently (backpressure)
	}
}

// drainLoop is the single goroutine that writes to disk sequentially.
func (tl *TrafficLogger) drainLoop() {
	for feature := range tl.ch {
		data, err := json.Marshal(feature)
		if err != nil {
			continue
		}
		data = append(data, '\n')

		tl.mu.Lock()
		if tl.written+int64(len(data)) > tl.maxSize {
			tl.rotate()
		}
		n, _ := tl.writer.Write(data)
		tl.written += int64(n)
		tl.mu.Unlock()
	}
	close(tl.done)
}

// rotate swaps the log file. Must be called under tl.mu lock.
func (tl *TrafficLogger) rotate() {
	tl.writer.Flush()
	tl.file.Close()
	os.Remove(tl.path + ".1")
	_ = os.Rename(tl.path, tl.path+".1")
	f, err := os.OpenFile(tl.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to rotate traffic log: %v\n", err)
		// Fallback: reopen the .1 file to avoid FD leak
		f, _ = os.OpenFile(tl.path+".1", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if f == nil {
			f, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		}
	}
	tl.file = f
	tl.writer = bufio.NewWriterSize(f, 64*1024)
	tl.written = 0
}

// Flush flushes the buffered writer.
func (tl *TrafficLogger) Flush() {
	if tl == nil {
		return
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.writer.Flush()
}

// Close gracefully shuts down the logger.
func (tl *TrafficLogger) Close() {
	if tl == nil {
		return
	}
	close(tl.ch)
	<-tl.done
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.writer.Flush()
	tl.file.Close()
}
