// Package privacy holds the client-address masking that gdpr_mode turns on,
// shared across every HTTP handler, CSV export, alert dispatcher, and live
// WebSocket feed.
package privacy

import (
	"database/sql"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultTTL is how long a database's gdpr_mode value is cached between reads.
const DefaultTTL = 30 * time.Second

var settingsByDB sync.Map // *sql.DB -> *Setting

// NetworkPrefix returns the canonical /24 (IPv4) or /64 (IPv6) prefix of ip.
// IPv4-mapped IPv6 addresses (::ffff:192.168.1.7) are unmapped to IPv4, and
// IPv6 zone identifiers (%eth0) are stripped. It reports false when ip cannot
// be parsed as an address.
func NetworkPrefix(ip string) (netip.Prefix, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Prefix{}, false
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is4() {
		return netip.PrefixFrom(addr, 24).Masked(), true
	}
	return netip.PrefixFrom(addr, 64).Masked(), true
}

// MaskIP masks an IPv4 address to /24 written a.b.c.x (192.168.1.7 becomes
// 192.168.1.x) and an IPv6 address to /64 written <prefix>::x
// (2001:db8:1:2:3:4:5:6 becomes 2001:db8:1:2::x). IPv4-mapped IPv6 addresses
// are handled as IPv4. Anything that does not parse as an address is returned
// as "unknown", never in clear.
func MaskIP(ip string) string {
	p, ok := NetworkPrefix(ip)
	if !ok {
		return "unknown"
	}
	a := p.Addr()
	if a.Is4() {
		b := a.As4()
		return strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[2])) + ".x"
	}
	return a.String() + "x"
}

// Setting reads gdpr_mode with a short cache, so per-row and per-message
// callers do not query the settings table on every line.
type Setting struct {
	db  *sql.DB
	ttl time.Duration

	mu      sync.RWMutex
	enabled bool
	exp     time.Time
}

// NewSetting reads gdpr_mode from db, cached for ttl.
func NewSetting(db *sql.DB, ttl time.Duration) *Setting {
	return &Setting{db: db, ttl: ttl}
}

// ForDB returns the shared Setting for db. Every handler and worker reading
// gdpr_mode from the same db shares this instance.
func ForDB(db *sql.DB) *Setting {
	if db == nil {
		return NewSetting(nil, DefaultTTL)
	}
	if s, ok := settingsByDB.Load(db); ok {
		return s.(*Setting)
	}
	s, _ := settingsByDB.LoadOrStore(db, NewSetting(db, DefaultTTL))
	return s.(*Setting)
}

// Enabled reports whether gdpr_mode is "true" in db, using ForDB(db).
func Enabled(db *sql.DB) bool {
	return ForDB(db).Enabled()
}

// Invalidate clears the cached value so the next Enabled call re-reads db.
func (s *Setting) Invalidate() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.exp = time.Time{}
	s.mu.Unlock()
}

// InvalidateDB clears the cached gdpr_mode value for db.
func InvalidateDB(db *sql.DB) {
	if db == nil {
		return
	}
	if s, ok := settingsByDB.Load(db); ok {
		s.(*Setting).Invalidate()
	}
}

// Enabled reports whether gdpr_mode is "true" in the settings table.
func (s *Setting) Enabled() bool {
	if s == nil || s.db == nil {
		return false
	}
	now := time.Now()
	s.mu.RLock()
	if now.Before(s.exp) {
		v := s.enabled
		s.mu.RUnlock()
		return v
	}
	s.mu.RUnlock()

	var val string
	on := false
	if err := s.db.QueryRow("SELECT setting_value FROM settings WHERE setting_name = 'gdpr_mode'").Scan(&val); err == nil {
		on = val == "true"
	}
	s.mu.Lock()
	s.enabled = on
	s.exp = now.Add(s.ttl)
	s.mu.Unlock()
	return on
}
