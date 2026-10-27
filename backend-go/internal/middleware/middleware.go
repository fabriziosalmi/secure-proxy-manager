// Package middleware provides HTTP middleware for authentication, CORS, and request IDs.
package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

type ctxKey string

// CtxUsername is the context key for the authenticated username.
const CtxUsername ctxKey = "username"

// CtxAuthVia is the context key for where the credential came from:
// auth.ViaBearer, auth.ViaBasic or auth.ViaCookie.
const CtxAuthVia ctxKey = "auth_via"

// Auth requires a valid JWT (Authorization: Bearer, or the browser's session
// cookie) or a Basic-Auth credential.
func Auth(svc *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, via, err := svc.AuthenticateRequest(r)
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="Secure Proxy Manager"`)
				writeJSON(w, http.StatusUnauthorized,
					map[string]string{"status": "error", "detail": err.Error()})
				return
			}
			ctx := context.WithValue(r.Context(), CtxUsername, username)
			ctx = context.WithValue(ctx, CtxAuthVia, via)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CSRFHeader is the header the UI sends on every request. A page on another
// origin cannot send it without a CORS preflight, which CORS answers only for
// the origins it allows.
const CSRFHeader = "X-Requested-With"

// CSRFHeaderValue is the value the UI sends in CSRFHeader.
const CSRFHeaderValue = "spm"

// SessionCSRF refuses a state-changing request that would be authenticated
// by the session cookie alone (no Authorization header) unless it carries
// CSRFHeader and, when the browser sends one, an Origin that is this host
// over https or one of CORS_ALLOWED_ORIGINS. The cookie is SameSite=Strict,
// so a cross-site page does not get it sent at all; this is the second
// layer. Requests with an Authorization header (API clients, Bearer or
// Basic) and safe methods pass untouched.
func SessionCSRF(cfg *config.Config) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(cfg.CORSAllowedOrigins))
	for _, o := range cfg.CORSAllowedOrigins {
		allowed[o] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			if r.Header.Get("Authorization") != "" {
				next.ServeHTTP(w, r)
				return
			}
			if c, err := r.Cookie(auth.SessionCookieName); err != nil || c.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			if r.Header.Get(CSRFHeader) != CSRFHeaderValue || !sameSiteOrigin(r, allowed) {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"status": "error",
					"detail": "cross-site request refused: a request authenticated by the session cookie must come from this dashboard",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// sameSiteOrigin reports whether r's Origin, if any, is an allowed origin or
// this host over https. nginx passes Host without the port, so the
// comparison is on the host name.
func sameSiteOrigin(r *http.Request, allowed map[string]struct{}) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // not sent by this browser; the CSRF header still had to be
	}
	if _, ok := allowed[origin]; ok {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return false
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.EqualFold(u.Hostname(), strings.Trim(host, "[]"))
}

// ServiceAuth gates an internal service-to-service endpoint on a dedicated
// bearer token rather than on the human admin credential.
//
// The WAF posts block notifications to /api/internal/alert and used to
// authenticate with BASIC_AUTH_USERNAME/PASSWORD — so the one container whose
// job is to parse attacker-controlled request bodies was also holding a
// credential that opens every administrative endpoint, over plain HTTP on the
// internal network. A token scoped to this one route removes that: a WAF
// compromise yields the ability to post alerts, and nothing else
// (SECURE-AUTH-02).
//
// When token is empty no dedicated credential is configured, and the endpoint
// falls back to `fallback` (the normal admin auth) so an in-place upgrade keeps
// delivering alerts instead of silently dropping them. When it IS set, admin
// auth is no longer accepted here: the point is that this route needs a
// credential the WAF has and an operator's browser session does not.
func ServiceAuth(token string, fallback func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	if token == "" {
		return fallback
	}
	want := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			// Constant time in the length that matters: ConstantTimeCompare
			// returns 0 for unequal lengths without comparing, and takes time
			// independent of WHERE two equal-length values first differ, so a
			// caller cannot walk the token out one byte at a time.
			if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="Secure Proxy Manager internal"`)
				writeJSON(w, http.StatusUnauthorized,
					map[string]string{"status": "error", "detail": "invalid service credential"})
				return
			}
			ctx := context.WithValue(r.Context(), CtxUsername, "waf")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// APIVersion stamps the contract version on every response so a client has
// something stable to assert on. Without it the only version a caller could
// read was the product build version from /api/health, which changes on every
// patch release whether or not any shape moved (SECURE-API-03).
func APIVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Version", config.APIVersion)
		next.ServeHTTP(w, r)
	})
}

// CORS appends per-request CORS headers for configured origins.
func CORS(cfg *config.Config) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(cfg.CORSAllowedOrigins))
	for _, o := range cfg.CORSAllowedOrigins {
		allowed[o] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			_, ok := allowed[origin]
			if !ok && origin != "" && r.Host != "" {
				// The same host over https (covers access by IP address). Plain
				// http is not echoed: the dashboard is served over https only,
				// and it would let a page on http://<host> make credentialed
				// requests.
				ok = origin == "https://"+r.Host
			}
			if ok {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, "+CSRFHeader+", X-SPM-Session")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequestID injects or propagates an X-Request-ID header.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 128 {
			id = fmt.Sprintf("%X", time.Now().UnixNano()>>20)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}

// MaxBodySize limits request body to prevent memory exhaustion DoS.
func MaxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxBytes {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds standard security response headers.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
