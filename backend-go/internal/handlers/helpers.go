package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// writeJSON serialises v as JSON and writes with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// writeError sends a JSON error response.
func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"status": "error", "detail": detail})
}

// writeOK sends a JSON success response.
func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "data": data})
}

// decode reads and JSON-decodes the request body into dst.
func decode(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 55*1024*1024)
	return json.NewDecoder(r.Body).Decode(dst)
}

// isValidCIDR returns true if s is a valid IP address or CIDR prefix.
func isValidCIDR(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// isSSRFTarget resolves the hostname in rawURL and returns true if ANY resolved
// IP is private, loopback, link-local, or otherwise non-routable.
func isSSRFTarget(rawURL string) (bool, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return true, fmt.Errorf("only http/https URLs allowed")
	}
	hostname := u.Hostname()
	if hostname == "" {
		return true, fmt.Errorf("empty hostname")
	}
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return true, fmt.Errorf("cannot resolve hostname: %w", err)
	}
	for _, addr := range addrs {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			continue
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return true, nil
		}
		// Block 0.0.0.0/8
		if ip.Is4() {
			a := ip.As4()
			if a[0] == 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// downloadWithRetry fetches a URL (max maxBytes) with up to 3 retries (exp backoff).
func downloadWithRetry(rawURL string, maxBytes int64) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<uint(attempt-1)) * time.Second)
		}
		body, err := downloadOnce(rawURL, maxBytes)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("after 3 attempts: %w", lastErr)
}

func downloadOnce(rawURL string, maxBytes int64) ([]byte, error) {
	client := &http.Client{Timeout: 180 * time.Second}
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
	var out []byte
	buf := make([]byte, 1<<20) // 1 MB chunks
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
	}
}

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
