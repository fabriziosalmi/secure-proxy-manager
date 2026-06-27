package main

import (
	"bufio"
	"encoding/json"
	"log"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

const (
	trafficLogPath             = "/data/waf_traffic.jsonl"
	trafficLogFallback         = "/tmp/waf_traffic.jsonl" // used when the primary path is read-only (e.g. read_only /data in prod)
	trafficLogMaxBytes         = 100 * 1 << 20            // 100 MB
	trafficLogFallbackMaxBytes = 16 * 1 << 20             // 16 MB — fallback is a memory-backed tmpfs; keep it small to avoid OOMing the container
	highEntropyThresh          = 4.5
	logQueueSize               = 4096 // Bounded channel — drops on overflow
)

// trafficLogDropped counts feature records dropped because the bounded queue was
// full. Exposed via /metrics so operators can see forensics being shed under
// load instead of it failing silently.
var trafficLogDropped atomic.Int64

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
	EventID         string   `json:"event_id"`
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

// openTrafficFile tries to open path for appending, creating its directory.
// Returns nil on any failure (e.g. read-only filesystem) so the caller can fall
// back to a writable location.
func openTrafficFile(path string) *os.File {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("traffic log: cannot create dir %s: %v\n", dir, err)
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("traffic log: cannot open %s: %v\n", path, err)
		return nil
	}
	return f
}

// newTrafficLogger opens the primary path; if that is unwritable (the prod
// read_only /data case — issue #112), it falls back to fallbackPath (tmpfs) so
// the feature/event-ID forensics keep flowing instead of silently no-op'ing.
func newTrafficLogger(path string, maxSize int64) *TrafficLogger {
	if envPath := os.Getenv("WAF_TRAFFIC_LOG_PATH"); envPath != "" {
		path = envPath
	}

	f := openTrafficFile(path)
	if f == nil && path != trafficLogFallback {
		log.Printf("traffic log: primary path %s unwritable, falling back to %s — forensics will NOT survive a restart\n", path, trafficLogFallback)
		path = trafficLogFallback
		f = openTrafficFile(path)
		// The fallback is a memory-backed tmpfs; shrink the rotation cap so the
		// log can't grow into the container's memory limit.
		if maxSize > trafficLogFallbackMaxBytes {
			maxSize = trafficLogFallbackMaxBytes
		}
	}
	if f == nil {
		log.Printf("traffic log: DISABLED — no writable path (records will be dropped, see waf_trafficlog_enabled metric)\n")
		return nil
	}
	log.Printf("traffic log: writing to %s\n", path)

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
		// Queue full — drop (backpressure), but count it so it's observable.
		trafficLogDropped.Add(1)
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
