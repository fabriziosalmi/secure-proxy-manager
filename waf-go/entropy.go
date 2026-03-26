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
	highEntropyThresh  = 4.5
	trafficLogPath     = "/data/waf_traffic.jsonl"
	trafficLogMaxBytes = 100 * 1 << 20 // 100 MB
)

// ── Shannon Entropy ─────────────────────────────────────────────────────────

// shannonEntropy calculates the Shannon entropy of a string in bits per char.
// High entropy (>4.5) suggests base64, encrypted, or obfuscated content.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return math.Round(entropy*100) / 100
}

// ── Traffic Feature Extraction ──────────────────────────────────────────────

// TrafficFeature captures per-request metadata for ML training.
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

// ── JSONL Traffic Logger ────────────────────────────────────────────────────

type TrafficLogger struct {
	mu      sync.Mutex
	writer  *bufio.Writer
	file    *os.File
	path    string
	maxSize int64
	written int64
}

var trafficLog *TrafficLogger

func newTrafficLogger(path string, maxSize int64) *TrafficLogger {
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)

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

	return &TrafficLogger{
		writer:  bufio.NewWriterSize(f, 64*1024),
		file:    f,
		path:    path,
		maxSize: maxSize,
		written: written,
	}
}

func (tl *TrafficLogger) Write(feature TrafficFeature) {
	if tl == nil {
		return
	}
	data, err := json.Marshal(feature)
	if err != nil {
		return
	}
	data = append(data, '\n')

	tl.mu.Lock()
	defer tl.mu.Unlock()

	// Rotate if needed
	if tl.written+int64(len(data)) > tl.maxSize {
		tl.writer.Flush()
		tl.file.Close()
		// Rename current to .1, discard .2
		os.Remove(tl.path + ".1")
		os.Rename(tl.path, tl.path+".1")
		f, err := os.OpenFile(tl.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Failed to rotate traffic log: %v\n", err)
			return
		}
		tl.file = f
		tl.writer = bufio.NewWriterSize(f, 64*1024)
		tl.written = 0
	}

	n, _ := tl.writer.Write(data)
	tl.written += int64(n)
}

func (tl *TrafficLogger) Flush() {
	if tl == nil {
		return
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.writer.Flush()
}
