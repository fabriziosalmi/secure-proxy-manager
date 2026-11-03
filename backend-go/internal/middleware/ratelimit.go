package middleware

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateLimiter implements a per-IP token bucket rate limiter.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   int     // max tokens
}

type bucket struct {
	tokens   float64
	lastTime time.Time
}

func newRateLimiter(requestsPerSecond float64, burst int) *rateLimiter {
	rl := &rateLimiter{
		buckets: make(map[string]*bucket),
		rate:    requestsPerSecond,
		burst:   burst,
	}
	// Periodic cleanup of stale buckets.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, b := range rl.buckets {
				if b.lastTime.Before(cutoff) {
					delete(rl.buckets, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[ip]
	now := time.Now()
	if !ok {
		rl.buckets[ip] = &bucket{tokens: float64(rl.burst) - 1, lastTime: now}
		return true
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastTime = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// GlobalRateLimit applies a per-IP token bucket rate limiter to all requests.
// rate: requests per second allowed per IP. burst: max burst size.
// A request for which an exempt predicate holds is not counted.
func GlobalRateLimit(rate float64, burst int, exempt ...func(*http.Request) bool) func(http.Handler) http.Handler {
	rl := newRateLimiter(rate, burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, ex := range exempt {
				if ex(r) {
					next.ServeHTTP(w, r)
					return
				}
			}
			ip := extractIP(r)
			if !rl.allow(ip) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, `{"status":"error","detail":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// internalServicePaths are the routes the WAF posts to with the service
// token.
var internalServicePaths = map[string]bool{"/api/internal/alert": true, "/api/internal/signals": true}

// InternalServiceRequest is an exemption for GlobalRateLimit: a request to
// one of the WAF's internal routes that carries the service token. The WAF
// sends block alerts and client signals from one address, so a burst of
// signals would spend the bucket its alerts need, and the token already
// tells the WAF from anyone else. With no token configured nothing is
// exempt.
func InternalServiceRequest(token string) func(*http.Request) bool {
	if token == "" {
		return func(*http.Request) bool { return false }
	}
	want := []byte(token)
	return func(r *http.Request) bool {
		if !internalServicePaths[r.URL.Path] {
			return false
		}
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		return subtle.ConstantTimeCompare([]byte(got), want) == 1
	}
}

// extractIP returns the client IP used for per-IP rate limiting.
//
// Trust model: X-Forwarded-For is honored ONLY when the immediate peer
// (r.RemoteAddr) is on a private/loopback network — i.e. when the request
// came through our own front-door reverse proxy on the docker network.
// We take the LEFT-MOST entry in X-Forwarded-For, which is the original
// client IP per RFC 7239 / common reverse-proxy convention. If the header
// is absent or the peer is public (no trusted hop), we fall back to
// r.RemoteAddr's host.
func extractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			for _, part := range splitComma(fwd) {
				if part != "" {
					return part
				}
			}
		}
	}
	return host
}

func splitComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			v := trimSpace(s[start:i])
			if v != "" {
				result = append(result, v)
			}
			start = i + 1
		}
	}
	v := trimSpace(s[start:])
	if v != "" {
		result = append(result, v)
	}
	return result
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && s[i] == ' ' {
		i++
	}
	for j > i && s[j-1] == ' ' {
		j--
	}
	return s[i:j]
}
