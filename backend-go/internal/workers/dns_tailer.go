package workers

import (
	"context"
	"database/sql"
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
	Track(func() {
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
			var persist bool
			offset, persist = tailOnce(db, hub, logPath, offset, dnsTail)
			if persist {
				writeOffset(posPath, offset)
			}
		}
	})
	log.Info().Str("path", logPath).Msg("dns tailer started")
}

// dnsTail is the dnsmasq log tailer. It shares tailOnce with the Squid tailer,
// and so its per-tick line cap: it had none, so a backlog was read into one
// slice, the same unbounded-memory shape the Squid tailer was capped for
// (SECURE-SCAL-02).
var dnsTail = tailSpec{
	name:     "dns tailer",
	parse:    parseDNSLine,
	maxLines: maxBatchLines,
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
