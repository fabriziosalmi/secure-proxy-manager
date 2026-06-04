package main

import (
	"html"
	"net"
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

		// URL-decode (tolerant: malformed escapes do not abort the whole string)
		s = percentDecodeTolerant(s)

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

// percentDecodeTolerant decodes %XX escapes, leaving malformed escapes (e.g.
// "%ZZ" or a trailing "%") as literal text. Unlike url.QueryUnescape — which is
// all-or-nothing and returns the input UNDECODED on the first bad escape — a
// single invalid token here does not abort decoding of the rest of the string.
// That all-or-nothing behavior was a full WAF bypass: appending one bad token
// (e.g. "%3Cscript%3E%ZZ") kept the real payload encoded and unscanned. "+" is
// decoded to a space to match query-string semantics.
func percentDecodeTolerant(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%':
			if i+2 < len(s) {
				if hi, ok := fromHex(s[i+1]); ok {
					if lo, ok2 := fromHex(s[i+2]); ok2 {
						b.WriteByte(hi<<4 | lo)
						i += 2
						continue
					}
				}
			}
			b.WriteByte('%') // malformed escape — keep literal, keep scanning
		case '+':
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// nonInspectableMedia are opaque binary media types that regex rules cannot
// meaningfully match. Most are already offloaded by the ICAP Transfer-Ignore
// list, so they rarely reach the WAF with a body.
var nonInspectableMedia = []string{
	"image/", "video/", "audio/", "font/", "application/font",
}

// shouldInspectBody decides whether a request body is worth scanning. Crucially
// it must NOT let the attacker-declared Content-Type be used to SKIP inspection:
// the previous text-only gate let any body through as long as it was labelled
// e.g. application/octet-stream. We therefore inspect by default and only skip a
// small set of genuinely opaque media types.
func shouldInspectBody(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	for _, skip := range nonInspectableMedia {
		if strings.HasPrefix(ct, skip) {
			return false
		}
	}
	return true
}
