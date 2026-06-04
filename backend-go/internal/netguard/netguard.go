// Package netguard centralises the network-safety primitives shared by the
// HTTP handlers and the background workers: SSRF-safe outbound fetching and
// IP/CIDR validation. Having one implementation prevents the import path and
// the auto-refresh worker from drifting apart (e.g. one gaining an RFC1918
// strip or DNS-rebinding guard the other lacks).
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// IsValidCIDR reports whether s is a valid IP address or CIDR prefix.
func IsValidCIDR(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// IsBlockedIP reports whether an IP must not be reached by server-side fetches
// or entered into a source blacklist: private, loopback, link-local,
// unspecified, multicast, 0.0.0.0/8 or the 100.64.0.0/10 CGNAT range.
func IsBlockedIP(ip net.IP) bool {
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

// IsLANBogonCIDR reports whether an IP/CIDR is a private/bogon/non-routable
// range that must not enter a SOURCE blacklist (it would block LAN clients).
func IsLANBogonCIDR(s string) bool {
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return IsBlockedIP(ipnet.IP)
	}
	if ip := net.ParseIP(s); ip != nil {
		return IsBlockedIP(ip)
	}
	return false
}

// IsSSRFTarget resolves the hostname in rawURL and returns true if ANY resolved
// IP is non-routable. Pre-flight only; SSRFSafeClient also validates at dial time.
func IsSSRFTarget(rawURL string) (bool, error) {
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
		if ip := net.ParseIP(addr); ip != nil && IsBlockedIP(ip) {
			return true, nil
		}
	}
	return false, nil
}

// SSRFSafeClient returns an HTTP client hardened against SSRF: it validates the
// destination IP AT DIAL TIME (closing the DNS-rebinding TOCTOU window) and
// re-validates every redirect hop, refusing any private/internal address.
func SSRFSafeClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			if ssrf, err := IsSSRFTarget(req.URL.String()); err != nil || ssrf {
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
					if IsBlockedIP(ipa.IP) {
						return nil, fmt.Errorf("blocked address %s for host %q", ipa.IP, host)
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
			},
		},
	}
}
