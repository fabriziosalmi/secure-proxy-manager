package workers

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/websocket"
)

// DNS query→client correlation has a tiny working set: a sinkhole reply follows
// its query within milliseconds, so entries are read once and then dead weight.
// The previous unbounded map leaked memory for the lifetime of the process on any
// network with churn (one entry per unique domain, forever). This bounded cache
// expires entries after a short TTL and enforces a hard size cap as a backstop.
const (
	dnsCacheMaxEntries = 8192
	dnsCacheTTL        = 2 * time.Minute
)

var dnsCache = newBoundedDNSCache(dnsCacheMaxEntries, dnsCacheTTL)

type dnsCacheEntry struct {
	ip      string
	expires int64 // unix nanoseconds
}

type boundedDNSCache struct {
	mu      sync.Mutex
	entries map[string]dnsCacheEntry
	max     int
	ttl     time.Duration
}

func newBoundedDNSCache(max int, ttl time.Duration) *boundedDNSCache {
	return &boundedDNSCache{entries: make(map[string]dnsCacheEntry), max: max, ttl: ttl}
}

func (c *boundedDNSCache) set(domain, ip string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[domain]; !exists && len(c.entries) >= c.max {
		c.evictLocked(now)
	}
	c.entries[domain] = dnsCacheEntry{ip: ip, expires: now.Add(c.ttl).UnixNano()}
}

func (c *boundedDNSCache) get(domain string, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[domain]
	if !ok {
		return "", false
	}
	if now.UnixNano() > e.expires {
		delete(c.entries, domain)
		return "", false
	}
	return e.ip, true
}

func (c *boundedDNSCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// evictLocked drops expired entries first and, if that does not free room,
// removes arbitrary entries until back under the cap. The caller must hold c.mu.
func (c *boundedDNSCache) evictLocked(now time.Time) {
	nowNano := now.UnixNano()
	for k, e := range c.entries {
		if nowNano > e.expires {
			delete(c.entries, k)
		}
	}
	// Hard backstop: Go randomises map iteration order, so this evicts a
	// pseudo-random sample rather than always the same keys.
	for k := range c.entries {
		if len(c.entries) < c.max {
			break
		}
		delete(c.entries, k)
	}
}

// StartDNSTailer tails the dnsmasq log and inserts blocked queries into proxy_logs.
func StartDNSTailer(ctx context.Context, db *sql.DB, logPath, stateDir string, hub *websocket.Hub) {
	posPath := filepath.Join(stateDir, filepath.Base(logPath)+".pos")
	go func() {
		offset := readOffset(posPath)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("dns tailer stopping")
				return
			case <-ticker.C:
			}
			metrics.WorkerHeartbeat("dns_tailer")

			f, err := os.Open(logPath)
			if err != nil {
				continue
			}
			fi, err := f.Stat()
			if err != nil {
				f.Close()
				continue
			}
			if fi.Size() < offset {
				offset = 0
			}
			if fi.Size() == offset {
				f.Close()
				continue
			}
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				f.Close()
				continue
			}
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 256*1024)
			batch := make([]map[string]any, 0, 256)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				if entry := parseDNSLine(line); entry != nil {
					batch = append(batch, entry)
				}
			}
			newOffset, seekErr := f.Seek(0, io.SeekCurrent)
			f.Close()

			if err := insertLogBatch(db, batch); err != nil {
				log.Warn().Err(err).Int("lines", len(batch)).Msg("dns tailer: batch insert failed, will retry")
				continue
			}
			for _, entry := range batch {
				if msg, err := json.Marshal(entry); err == nil {
					select {
					case hub.Broadcast <- msg:
					default:
					}
				}
			}

			if seekErr == nil {
				offset = newOffset
			} else {
				offset = fi.Size()
			}
			writeOffset(posPath, offset)
		}
	}()
	log.Info().Str("path", logPath).Msg("dns tailer started")
}

func parseDNSLine(line string) map[string]any {
	// Parse queries: query[A] evil.com from 192.168.1.5
	if strings.Contains(line, "query[") {
		parts := strings.Split(line, "query[")
		if len(parts) > 1 {
			subparts := strings.Fields(parts[1])
			if len(subparts) >= 4 && subparts[2] == "from" {
				// subparts[1] is domain (e.g. "evil.com"), subparts[3] is client IP
				domain := subparts[1]
				ip := subparts[3]
				dnsCache.set(domain, ip, time.Now())
			}
		}
		return nil
	}

	// Parse blocked sinkhole resolutions: config evil.com is 0.0.0.0
	if strings.HasSuffix(line, "is 0.0.0.0") || strings.HasSuffix(line, "is ::") {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			domain := fields[len(fields)-3]
			clientIP, ok := dnsCache.get(domain, time.Now())
			if !ok {
				clientIP = "127.0.0.1"
			}
			return map[string]any{
				"timestamp":      time.Now().UTC().Format("2006-01-02 15:04:05"),
				"unix_timestamp": time.Now().Unix(),
				"client_ip":      clientIP,
				"source_ip":      clientIP,
				"method":         "DNS",
				"destination":    domain,
				"status":         "DNS_SINKHOLE/0.0.0.0",
				"bytes":          int64(0),
				"elapsed_ms":     int64(0),
				"blocked":        int(1),
			}
		}
	}

	return nil
}
