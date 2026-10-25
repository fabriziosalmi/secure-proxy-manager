// Package privacy holds the client-address masking that gdpr_mode turns on,
// shared by the log API and the live log feed so the two cannot disagree.
package privacy

import (
	"database/sql"
	"strings"
	"sync"
	"time"
)

// MaskIP anonymizes the last octet of an IPv4 address (192.168.1.7 becomes
// 192.168.1.x) or the last group of an IPv6 address.
func MaskIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		parts[3] = "x"
		return strings.Join(parts, ".")
	}
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		return ip[:idx] + ":x"
	}
	return ip
}

// Setting reads gdpr_mode with a short cache, so the per-row and per-message
// paths do not query the database each time. A change is in effect within
// ttl.
type Setting struct {
	db  *sql.DB
	ttl time.Duration

	mu    sync.RWMutex
	value bool
	read  time.Time
}

// NewSetting reads gdpr_mode from db, cached for ttl.
func NewSetting(db *sql.DB, ttl time.Duration) *Setting {
	return &Setting{db: db, ttl: ttl}
}

// Enabled reports whether client addresses are masked.
func (s *Setting) Enabled() bool {
	if s == nil || s.db == nil {
		return false
	}
	s.mu.RLock()
	if !s.read.IsZero() && time.Since(s.read) < s.ttl {
		v := s.value
		s.mu.RUnlock()
		return v
	}
	s.mu.RUnlock()
	var val string
	enabled := false
	if err := s.db.QueryRow("SELECT setting_value FROM settings WHERE setting_name = 'gdpr_mode'").Scan(&val); err == nil {
		enabled = val == "true"
	}
	s.mu.Lock()
	s.value, s.read = enabled, time.Now()
	s.mu.Unlock()
	return enabled
}
