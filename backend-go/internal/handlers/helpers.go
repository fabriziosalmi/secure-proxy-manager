package handlers

import (
	"bytes"
	"context"
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

// isValidCIDR returns true if s is a valid IP address or CIDR prefix.
func isValidCIDR(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

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

// isBlockedIP reports whether an IP must not be reached by server-side fetches:
// private, loopback, link-local, unspecified, multicast, 0.0.0.0/8 or the
// 100.64.0.0/10 CGNAT range (commonly fronting internal infra / metadata).
func isBlockedIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	if a.Is4() {
		b := a.As4()
		if b[0] == 0 { // 0.0.0.0/8
			return true
		}
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 { // 100.64.0.0/10 CGNAT
			return true
		}
	}
	return false
}

// isLANBogonCIDR reports whether an IP/CIDR is a private (RFC1918), loopback,
// link-local, CGNAT or otherwise non-routable range. Such entries must NOT enter
// the SOURCE ip_blacklist: it is matched as `acl ip_blacklist src` and denied
// before `allow localnet`/`allow localhost`, so adding e.g. 192.168.0.0/16 (as
// Firehol/bogon feeds do) would block the proxy's own LAN clients.
func isLANBogonCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return isBlockedIP(ipnet.IP)
	}
	if ip := net.ParseIP(s); ip != nil {
		return isBlockedIP(ip)
	}
	return false
}

// isSSRFTarget resolves the hostname in rawURL and returns true if ANY resolved
// IP is non-routable. This is the early pre-flight check; the actual fetch is
// additionally guarded at dial time by ssrfSafeClient (see below), so a DNS
// answer that changes between this check and the dial cannot bypass protection.
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
		if ip := net.ParseIP(addr); ip != nil && isBlockedIP(ip) {
			return true, nil
		}
	}
	return false, nil
}

// ssrfSafeClient returns an HTTP client hardened against SSRF. Unlike a one-shot
// pre-check, it validates the destination IP AT DIAL TIME — the IP it validates
// is the exact IP it connects to — which closes the DNS-rebinding TOCTOU window
// between resolution and connection. It also re-validates every redirect hop, so
// a 30x to http://169.254.169.254/ (or any internal host) is refused rather than
// followed.
func ssrfSafeClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			if ssrf, err := isSSRFTarget(req.URL.String()); err != nil || ssrf {
				return fmt.Errorf("redirect to disallowed target %q", req.URL.Host)
			}
			return nil
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
				if len(ips) == 0 {
					return nil, fmt.Errorf("no addresses for %q", host)
				}
				for _, ipa := range ips {
					if isBlockedIP(ipa.IP) {
						return nil, fmt.Errorf("blocked address %s for host %q", ipa.IP, host)
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
			},
		},
	}
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
