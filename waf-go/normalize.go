package main

import (
	"html"
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

// isLANHost returns true if the host is a private/LAN IP address.
// These destinations should bypass WAF inspection (not SSRF).
func isLANHost(host string) bool {
	// Strip port
	h := host
	if strings.Contains(h, "[") && strings.Contains(h, "]") {
		// IPv6 with port: [::1]:8080
		idx := strings.LastIndex(h, "]")
		h = h[1:idx]
	} else if strings.Count(h, ":") == 1 {
		// IPv4 with port: 127.0.0.1:8080
		idx := strings.LastIndex(h, ":")
		h = h[:idx]
	}
	// Note: bare IPv6 like ::1 should not be stripped if it has no brackets/port
	
	return strings.HasPrefix(h, "10.") ||
		strings.HasPrefix(h, "192.168.") ||
		strings.HasPrefix(h, "172.16.") || strings.HasPrefix(h, "172.17.") ||
		strings.HasPrefix(h, "172.18.") || strings.HasPrefix(h, "172.19.") ||
		strings.HasPrefix(h, "172.2") || strings.HasPrefix(h, "172.30.") ||
		strings.HasPrefix(h, "172.31.") ||
		h == "localhost" || h == "127.0.0.1" || h == "::1"
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
