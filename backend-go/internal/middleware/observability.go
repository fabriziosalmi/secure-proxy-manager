package middleware

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// respRecorder captures status code and response size while transparently
// delegating optional interfaces (Hijacker for WebSocket upgrades, Flusher for
// streaming) so it can sit in front of every handler without breaking them.
type respRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (r *respRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *respRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status = http.StatusOK
		r.wrote = true
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (r *respRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (r *respRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// routePattern returns the chi route pattern matched for r, or "unmatched".
// It must be called AFTER the handler ran, once chi has populated the context.
func routePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if p := rc.RoutePattern(); p != "" {
			return p
		}
	}
	return "unmatched"
}

// Metrics records RED metrics (rate, errors via status, duration) for every
// request, labelled by method, matched route pattern and status.
func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		metrics.HTTPInFlight.Inc()
		rec := &respRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		metrics.HTTPInFlight.Dec()

		route := routePattern(r)
		status := strconv.Itoa(rec.status)
		metrics.HTTPRequests.WithLabelValues(r.Method, route, status).Inc()
		metrics.HTTPDuration.WithLabelValues(r.Method, route, status).Observe(time.Since(start).Seconds())
	})
}

// noLogPaths are health/scrape endpoints excluded from the access log to keep it
// signal-rich (Prometheus and Docker hit these every few seconds).
var noLogPaths = map[string]struct{}{
	"/metrics": {}, "/health": {}, "/livez": {}, "/readyz": {},
	"/api/health": {}, "/api/ready": {},
}

// AccessLog emits one structured zerolog line per request (method, path, status,
// bytes, duration, request_id, remote) — the access log the backend previously
// lacked. Health/scrape paths are skipped.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, skip := noLogPaths[r.URL.Path]; skip {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &respRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		remote := r.RemoteAddr
		if host, _, err := net.SplitHostPort(remote); err == nil {
			remote = host
		}
		ev := log.Info()
		if rec.status >= 500 {
			ev = log.Error()
		} else if rec.status >= 400 {
			ev = log.Warn()
		}
		ev.Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", rec.status).
			Int("bytes", rec.bytes).
			Dur("duration", time.Since(start)).
			Str("request_id", w.Header().Get("X-Request-ID")).
			Str("remote", remote).
			Msg("http_request")
	})
}
