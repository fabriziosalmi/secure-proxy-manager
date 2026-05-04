package main

import (
	"html"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// textContentTypes lists Content-Type prefixes for which body inspection is meaningful.
var textContentTypes = []string{
	"application/x-www-form-urlencoded",
	"application/json",
	"application/xml",
	"text/xml",
	"text/",
	"multipart/form-data",
}

// ── Input normalization ─────────────────────────────────────────────────────

var (
	reDoubleEncode = regexp.MustCompile(`%25([0-9a-fA-F]{2})`)
	reNullBytes    = regexp.MustCompile("(%00|\\\\x00|&#0+;?|\x00)")
	reMultiSpace   = regexp.MustCompile(`\s{2,}`)
	reAllSpace     = regexp.MustCompile(`\s+`)
)

// normalizeInput applies anti-evasion transformations to the input.
// It iterates URL decoding up to maxDecodeIterations times to defeat
// multi-layer encoding evasion (e.g. triple encoding %25252e).
func normalizeInput(input string) string {
	const maxDecodeIterations = 10

	s := input
	for i := 0; i < maxDecodeIterations; i++ {
		// Double-decode: %252e → %2e
		prev := s
		s = reDoubleEncode.ReplaceAllString(s, "%$1")

		// URL-decode
		if decoded, err := url.QueryUnescape(strings.ReplaceAll(s, "+", " ")); err == nil {
			s = decoded
		}

		// Stop when decoding produces no further change
		if s == prev {
			break
		}
	}

	// HTML entity decode
	s = html.UnescapeString(s)

	// Remove null bytes
	s = reNullBytes.ReplaceAllString(s, "")

	// Collapse whitespace
	s = reMultiSpace.ReplaceAllString(s, " ")

	return s
}

// compactInput strips ALL whitespace — catches evasion via space insertion
// inside keywords (e.g. "<scr ipt>" → "<script>").
func compactInput(s string) string {
	return reAllSpace.ReplaceAllString(s, "")
}

// isLANHost returns true if the host is a private/LAN destination.
// These destinations should bypass WAF inspection (not SSRF).
//
// SECURITY: previous implementation used naive string prefix matching like
// strings.HasPrefix(h, "172.2") which matched public IPs in 172.20.0.0/8
// (e.g. 172.200.0.1) and incorrectly bypassed the WAF for them. We now use
// net.ParseIP + IsPrivate/IsLoopback/IsLinkLocalUnicast which correctly
// covers RFC1918 (10/8, 172.16/12, 192.168/16), 127/8, ::1, fc00::/7, fe80::/10.
func isLANHost(host string) bool {
	if host == "" {
		return false
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		// SplitHostPort fails on bare hostnames or bare IPv6 like "::1"
		h = host
	}
	// Strip surrounding brackets from bare bracketed IPv6: "[::1]"
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		// Not an IP literal — treat as public hostname.
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func isTextContent(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, prefix := range textContentTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}
