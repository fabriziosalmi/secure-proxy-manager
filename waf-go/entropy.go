package main

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
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

// trafficLogSinkDropped counts records discarded because the log file could not
// be (re)opened, as distinct from trafficLogDropped (queue full). Both are
// forensics lost; the operator needs to tell "shedding load" from "the disk is
// gone".
var trafficLogSinkDropped atomic.Int64

// trafficLogRetryEvery bounds how often a logger whose sink is down tries to
// reopen it, so a dead disk costs one failed open per interval, not one per
// record.
const trafficLogRetryEvery = 30 * time.Second

// ── Traffic Feature Extraction ──────────────────────────────────────────────

type TrafficFeature struct {
	EventID   string `json:"event_id"`
	Timestamp string `json:"ts"`
	// source_ip, matching the backend's schema and its wire shape. The two
	// records are designed to be correlated through event_id, and calling the
	// same fact client_ip here and source_ip there meant an analyst joining them
	// had to know both names for one concept. The backend collapsed a three-way
	// split of this same field; the WAF was not included in that pass, so the
	// split sat on the service boundary instead of inside one service
	// (SECURE-DOM-03).
	ClientIP        string   `json:"source_ip"`
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

	// sinkDown is set when the file could not be reopened after rotation and
	// the fallback failed too. While it is set, file and writer are nil,
	// records are counted in trafficLogSinkDropped, and drainLoop retries the
	// reopen every retryEvery. It replaces the old behaviour of pointing the
	// writer at /dev/null, which discarded every later record with no signal
	// and never recovered.
	sinkDown     atomic.Bool
	retryEvery   time.Duration
	lastReopenAt time.Time
}

// Writable reports whether records are reaching a file.
func (tl *TrafficLogger) Writable() bool { return tl != nil && !tl.sinkDown.Load() }

var trafficLog *TrafficLogger

// openTrafficFile tries to open path for appending, creating its directory.
// Returns nil on any failure (e.g. read-only filesystem) so the caller can fall
// back to a writable location.
func openTrafficFile(path string) *os.File {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		slog.Warn("traffic log: cannot create directory", "dir", dir, "error", err.Error())
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		slog.Warn("traffic log: cannot open file", "path", path, "error", err.Error())
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
		slog.Warn("traffic log: primary path unwritable, falling back; forensics will NOT survive a restart",
			"path", path, "fallback", trafficLogFallback)
		path = trafficLogFallback
		f = openTrafficFile(path)
		// The fallback is a memory-backed tmpfs; shrink the rotation cap so the
		// log can't grow into the container's memory limit.
		if maxSize > trafficLogFallbackMaxBytes {
			maxSize = trafficLogFallbackMaxBytes
		}
	}
	if f == nil {
		slog.Error("traffic log: DISABLED, no writable path; records will be dropped (see waf_trafficlog_enabled)")
		return nil
	}
	slog.Info("traffic log: writing", "path", path)

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

		retryEvery: trafficLogRetryEvery,
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
		if tl.file == nil {
			tl.tryReopen()
		} else if tl.written+int64(len(data)) > tl.maxSize {
			tl.rotate()
		}
		if tl.file == nil {
			trafficLogSinkDropped.Add(1)
			tl.mu.Unlock()
			continue
		}
		n, _ := tl.writer.Write(data)
		tl.written += int64(n)
		tl.mu.Unlock()
	}
	close(tl.done)
}

// rotate swaps the log file. Must be called under tl.mu lock.
func (tl *TrafficLogger) rotate() {
	// A failed flush here silently drops the tail of the previous file — the
	// most recent forensic records, which are the ones an incident needs.
	if err := tl.writer.Flush(); err != nil {
		slog.Error("traffic log: flush before rotate failed, records lost", "error", err.Error())
	}
	_ = tl.file.Close()
	_ = os.Remove(tl.path + ".1")
	_ = os.Rename(tl.path, tl.path+".1")
	f, err := os.OpenFile(tl.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		slog.Error("traffic log: rotation failed", "path", tl.path, "error", err.Error())
		// Fall back to appending to the rotated file rather than losing the
		// sink and leaking the descriptor.
		f, err = os.OpenFile(tl.path+".1", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			tl.markDown(err)
			return
		}
	}
	tl.file = f
	tl.writer = bufio.NewWriterSize(f, 64*1024)
	tl.written = 0
}

// markDown records that no file could be opened. Must be called under tl.mu.
func (tl *TrafficLogger) markDown(cause error) {
	tl.file = nil
	tl.writer = nil
	tl.lastReopenAt = time.Now()
	if tl.sinkDown.CompareAndSwap(false, true) {
		slog.Error("traffic log: DOWN, no file could be opened; forensic records are being dropped (waf_trafficlog_sink_dropped_total)",
			"path", tl.path, "error", cause.Error(), "retry_every", tl.retryEvery.String())
	}
}

// tryReopen retries the sink, at most once per retryEvery. Must be called under
// tl.mu with tl.file == nil.
func (tl *TrafficLogger) tryReopen() {
	if time.Since(tl.lastReopenAt) < tl.retryEvery {
		return
	}
	tl.lastReopenAt = time.Now()
	if err := os.MkdirAll(filepath.Dir(tl.path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(tl.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	info, _ := f.Stat()
	tl.file = f
	tl.writer = bufio.NewWriterSize(f, 64*1024)
	tl.written = 0
	if info != nil {
		tl.written = info.Size()
	}
	tl.sinkDown.Store(false)
	slog.Info("traffic log: recovered", "path", tl.path)
}

// Flush flushes the buffered writer.
func (tl *TrafficLogger) Flush() {
	if tl == nil {
		return
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if tl.writer == nil {
		return
	}
	if err := tl.writer.Flush(); err != nil {
		slog.Error("traffic log: flush failed, buffered records lost", "error", err.Error())
	}
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
	if tl.writer == nil || tl.file == nil {
		return
	}
	if err := tl.writer.Flush(); err != nil {
		slog.Error("traffic log: final flush failed, records lost", "error", err.Error())
	}
	_ = tl.file.Close()
}
