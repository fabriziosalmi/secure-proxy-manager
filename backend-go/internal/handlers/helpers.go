package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/netguard"
)

// writeJSON serialises v as JSON and writes with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// writeError sends a JSON error response. The shape is contractual —
// docs/api/reference.md states that errors are ALWAYS
// {"status": "error", "detail": "..."} — so detail must be a stable string
// this project controls, never a message from a dependency.
func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"status": "error", "detail": detail})
}

// writeInternalError reports a server-side failure to the caller with a stable
// message, and puts the real cause in the log where it belongs.
//
// Fourteen handlers used to pass err.Error() straight into detail, so a
// contractual response string was whatever text the SQLite driver produced:
// unstable across a dependency bump this project's changelog would not mention,
// and useless to a UI that wanted to map it to something actionable
// (SECURE-API-04).
func writeInternalError(w http.ResponseWriter, op string, err error) {
	log.Error().Str("op", op).Err(err).Msg("request failed")
	writeJSON(w, http.StatusInternalServerError, map[string]string{
		"status": "error",
		"code":   "internal_error",
		"detail": "the server could not complete the request",
	})
}

// ListMeta is the pagination envelope shared by every collection endpoint.
type ListMeta struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// writeList is the single way a collection leaves this API.
//
// Collections used to come back in three incompatible shapes: the collection
// under data with the pagination as top-level siblings, the collection under
// data with no metadata at all, and the collection nested one level deeper
// under data.clients with its count beside it. No client-side helper could
// read a list without special-casing the endpoint, which is why the frontend
// carried `data?.data ?? data?.logs` (SECURE-API-02).
//
// The top-level total/limit/offset are still emitted alongside meta, marked
// deprecated: this API is published (docs/api/, an MCP server) so the old shape
// is kept reachable for a release rather than removed silently. Read meta.
func writeList(w http.ResponseWriter, items any, meta ListMeta) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   items,
		"meta":   meta,
		// Deprecated: read meta instead. Removed in the next contract version.
		"total":  meta.Total,
		"limit":  meta.Limit,
		"offset": meta.Offset,
	})
}

// writeOK sends a JSON success response.
func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "data": data})
}

// Network-safety primitives live in internal/netguard so the handlers and the
// background workers share one implementation. These thin wrappers keep the
// existing handler call sites unchanged.
func isValidCIDR(s string) bool           { return netguard.IsValidCIDR(s) }
func isBlockedIP(ip net.IP) bool          { return netguard.IsBlockedIP(ip) }
func isLANBogonCIDR(s string) bool        { return netguard.IsLANBogonCIDR(s) }
func isSSRFTarget(u string) (bool, error) { return netguard.IsSSRFTarget(u) }
func ssrfSafeClient() *http.Client        { return netguard.SSRFSafeClient() }

// internallyManagedSettings are written by the application itself (not the
// operator) and must never be set through the generic bulk-update or
// restore-config paths, where a crafted payload could otherwise rewrite trusted
// internal state (e.g. clearing the "admin password changed" flag).
var internallyManagedSettings = map[string]bool{
	"default_password_changed": true,
}

// isWritableSettingKey reports whether a settings key may be written through the
// bulk-update / restore-config endpoints: it must match the key-name convention,
// be within the length bound, and not be an internally-managed key.
func isWritableSettingKey(key string) bool {
	return len(key) <= 100 && validKeyRE.MatchString(key) && !internallyManagedSettings[key]
}

// downloadWithRetry fetches a URL (max maxBytes) with up to 3 retries (exp backoff).
func downloadWithRetry(rawURL string, maxBytes int64) ([]byte, error) {
	retryDelay := [3]time.Duration{0, 1 * time.Second, 2 * time.Second}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		time.Sleep(retryDelay[attempt])
		body, err := downloadOnce(rawURL, maxBytes)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("after 3 attempts: %w", lastErr)
}

func downloadOnce(rawURL string, maxBytes int64) ([]byte, error) {
	// SSRF-safe client validates the destination IP at dial time and on every
	// redirect, so DNS rebinding between the pre-check and the fetch cannot reach
	// internal addresses.
	client := ssrfSafeClient()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SecureProxyManager/2.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	lr := &limitedReader{r: resp.Body, n: maxBytes}
	data, err := readAll(lr)
	if lr.exceeded {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBytes)
	}
	return data, err
}

type limitedReader struct {
	r        interface{ Read([]byte) (int, error) }
	n        int64
	read     int64
	exceeded bool
}

func (lr *limitedReader) Read(p []byte) (int, error) {
	n, err := lr.r.Read(p)
	lr.read += int64(n)
	if lr.read > lr.n {
		lr.exceeded = true
		return 0, fmt.Errorf("size limit exceeded")
	}
	return n, err
}

func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(ioReader{r}); err != nil && !errors.Is(err, io.EOF) {
		return buf.Bytes(), err
	}
	return buf.Bytes(), nil
}

// ioReader wraps a minimal Read interface into io.Reader for bytes.Buffer.ReadFrom.
type ioReader struct {
	r interface{ Read([]byte) (int, error) }
}

func (w ioReader) Read(p []byte) (int, error) { return w.r.Read(p) }

// extractDomain parses a destination like "http://example.com:443/path" → "example.com".
func extractDomain(dest string) string {
	d := dest
	for _, pfx := range []string{"https://", "http://", "ftp://"} {
		if strings.HasPrefix(d, pfx) {
			d = d[len(pfx):]
			break
		}
	}
	d = strings.SplitN(d, "/", 2)[0]
	d = strings.SplitN(d, ":", 2)[0]
	return strings.ToLower(d)
}

// maskIP anonymizes the last octet of an IPv4 address: 192.168.1.7 → 192.168.1.x
func maskIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		parts[3] = "x"
		return strings.Join(parts, ".")
	}
	// IPv6 or other — mask last segment
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		return ip[:idx] + ":x"
	}
	return ip
}
