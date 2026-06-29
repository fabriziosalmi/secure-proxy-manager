package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// ETag buffers a GET response, derives a strong validator from the body hash,
// and serves 304 Not Modified when the client's If-None-Match matches. It lets
// the browser revalidate expensive analytics payloads cheaply: the handler still
// runs, but an unchanged response skips serialising the body over the wire.
//
// It is intended for small, plain-JSON endpoints. It buffers the whole body, so
// do not apply it to streaming/SSE/WebSocket routes.
func ETag(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}

		rec := &etagRecorder{ResponseWriter: w, status: http.StatusOK, buf: &bytes.Buffer{}}
		next.ServeHTTP(rec, r)
		body := rec.buf.Bytes()

		// Only validators for cacheable 200s with a body. Everything else is
		// replayed verbatim.
		if rec.status == http.StatusOK && len(body) > 0 {
			sum := sha256.Sum256(body)
			etag := `"` + hex.EncodeToString(sum[:16]) + `"`
			w.Header().Set("ETag", etag)
			if w.Header().Get("Cache-Control") == "" {
				w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
			}
			if etagMatches(r.Header.Get("If-None-Match"), etag) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}

		w.WriteHeader(rec.status)
		w.Write(body) //nolint:errcheck
	})
}

// etagMatches reports whether the If-None-Match header satisfies etag. It honours
// "*", comma-separated lists, and weak ("W/") prefixes per RFC 7232.
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	if strings.TrimSpace(header) == "*" {
		return true
	}
	for _, part := range strings.Split(header, ",") {
		p := strings.TrimSpace(part)
		p = strings.TrimPrefix(p, "W/")
		if p == etag {
			return true
		}
	}
	return false
}

// etagRecorder buffers the body and captures the status without writing through
// to the underlying ResponseWriter, so the ETag middleware can decide between a
// 200 replay and a 304 after the handler has finished. Headers set by the
// handler (e.g. Content-Type) land on the real writer directly via the embedded
// ResponseWriter and are preserved.
type etagRecorder struct {
	http.ResponseWriter
	status int
	buf    *bytes.Buffer
}

func (e *etagRecorder) WriteHeader(code int) { e.status = code }

func (e *etagRecorder) Write(b []byte) (int, error) { return e.buf.Write(b) }
