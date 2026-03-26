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
func normalizeInput(input string) string {
	// Double-decode: %252e → %2e → .
	s := reDoubleEncode.ReplaceAllString(input, "%$1")

	// URL-decode
	if decoded, err := url.QueryUnescape(strings.ReplaceAll(s, "+", " ")); err == nil {
		s = decoded
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
	if idx := strings.LastIndex(h, ":"); idx > 0 {
		h = h[:idx]
	}
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
