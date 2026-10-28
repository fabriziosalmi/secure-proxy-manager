package handlers

import (
	"database/sql"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"sort"
	"sync"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/sources"
)

// InternalSources finds the internal source addresses (sources.Classifier)
// that appear in proxy_logs, so the statistics can leave them out of client
// counts and the client list can mark them.
//
// The log stores addresses as text and has an index on source_ip, so each
// internal subnet is one index range ("172.18." for 172.18.0.0/16). Walking a
// range by its distinct values, one MIN per address, reads a handful of index
// entries instead of every row of a busy internal source.
type InternalSources struct {
	db *sql.DB
	c  *sources.Classifier

	mu  sync.Mutex
	ips []string
	at  time.Time
}

// NewInternalSources returns the finder for db with classifier c; a nil c
// knows loopback only.
func NewInternalSources(db *sql.DB, c *sources.Classifier) *InternalSources {
	if c == nil {
		c = sources.Fixed(sources.Snapshot{})
	}
	return &InternalSources{db: db, c: c}
}

// internalSourcesTTL matches lifetimeCountsTTL: a new internal address is
// counted as a client for at most this long.
const internalSourcesTTL = 25 * time.Second

// maxPerRange caps the addresses read from one range. A stack subnet holds a
// few containers; the cap only bounds a pathological log.
const maxPerRange = 1024

// Classify says whether ip is internal and what it is.
func (s *InternalSources) Classify(ip string) (bool, string) {
	return s.c.Snapshot().Classify(ip)
}

// Present returns the internal addresses in proxy_logs, sorted, refreshed at
// most once per internalSourcesTTL. The slice is shared: do not modify it.
func (s *InternalSources) Present() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.at.IsZero() && time.Since(s.at) < internalSourcesTTL {
		return s.ips
	}
	s.ips, s.at = s.scan(), time.Now()
	return s.ips
}

// forget drops the cached list, after the logs were cleared.
func (s *InternalSources) forget() {
	s.mu.Lock()
	s.at = time.Time{}
	s.mu.Unlock()
}

func (s *InternalSources) scan() []string {
	snap := s.c.Snapshot()
	seen := map[string]struct{}{}
	for _, r := range snap.Ranges() {
		var next sql.NullString
		err := s.db.QueryRow(`SELECT MIN(source_ip) FROM proxy_logs WHERE source_ip >= ? AND source_ip < ?`, r.Lo, r.Hi).Scan(&next)
		for i := 0; err == nil && next.Valid && i < maxPerRange; i++ {
			if internal, _ := snap.Classify(next.String); internal {
				seen[next.String] = struct{}{}
			}
			err = s.db.QueryRow(`SELECT MIN(source_ip) FROM proxy_logs WHERE source_ip > ? AND source_ip < ?`, next.String, r.Hi).Scan(&next)
		}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// notInternal is the condition that keeps rows whose source is not one of
// ips, with its arguments. A row with no source address is kept: it is not
// known to be internal.
func notInternal(ips []string) (database.SQLText, []any) {
	if len(ips) == 0 {
		return "1 = 1", nil
	}
	return "IFNULL(source_ip, '') NOT IN (" + placeholders(len(ips)) + ")", toArgs(ips)
}

// onlyInternal is the condition that keeps rows whose source is one of ips.
func onlyInternal(ips []string) (database.SQLText, []any) {
	if len(ips) == 0 {
		return "0 = 1", nil
	}
	return "source_ip IN (" + placeholders(len(ips)) + ")", toArgs(ips)
}

func placeholders(n int) database.SQLText {
	return database.Placeholders(n)
}

func toArgs(ips []string) []any {
	out := make([]any, len(ips))
	for i, ip := range ips {
		out[i] = ip
	}
	return out
}
