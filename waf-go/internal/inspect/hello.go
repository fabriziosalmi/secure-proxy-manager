package inspect

import (
	"encoding/base64"
	"net"
	"net/http"
	"strings"

	"secure-proxy-waf/internal/engine"
)

// Hello is what Squid saw of a CONNECT's first client bytes when it peeked at
// them without decrypting (ssl_bump peek, then splice). Squid then sends the
// same CONNECT through REQMOD a second time, with two ICAP headers set by
// adaptation_meta: X-SPM-SNI (%ssl::>sni) and X-SPM-Client-Hello
// (%>handshake, base64). Squid writes "-" for a value it does not have. A
// non-nil Hello on an Inspection marks that second pass.
type Hello struct {
	// SNI is the server name the client asked for, lower case, without a
	// trailing dot; "" when the handshake named none.
	SNI string
	// SNIInvalid is a server name that is not a host name (letters, digits,
	// hyphens and underscores in dot-separated labels).
	SNIInvalid bool
	// TLS says the bytes start a TLS ClientHello. A tunnel Squid let through
	// as not TLS (on_unsupported_protocol tunnel) has TLS false.
	TLS bool
	// JA4 is the hello's JA4 fingerprint; "" when the bytes did not parse
	// as a whole ClientHello or were over maxHelloBase64.
	JA4 string
}

// maxHelloBase64 bounds what is decoded for the fingerprint. A ClientHello
// with post-quantum key shares is about 2 KiB of base64 (Squid 7.7, curl).
const maxHelloBase64 = 64 << 10

// ParseHello reads the two ICAP header values of a peeked CONNECT. It
// returns nil when there is no handshake, which is every REQMOD but the
// second pass of a CONNECT.
func ParseHello(sniHeader, helloHeader string) *Hello {
	helloHeader = strings.TrimSpace(helloHeader)
	if helloHeader == "" || helloHeader == "-" {
		return nil
	}
	h := &Hello{TLS: startsClientHello(helloHeader)}
	if h.TLS && len(helloHeader) <= maxHelloBase64 {
		if raw, err := base64.StdEncoding.DecodeString(helloHeader); err == nil {
			h.JA4, _ = JA4(raw)
		}
	}
	sni := strings.TrimSpace(sniHeader)
	if sni == "" || sni == "-" {
		return h
	}
	h.SNI = strings.TrimSuffix(strings.ToLower(sni), ".")
	h.SNIInvalid = !isHostName(h.SNI)
	return h
}

// startsClientHello reports whether the base64 bytes begin a TLS record of
// type handshake (0x16, version 3.x) holding a ClientHello (type 1). Only the
// first six bytes are decoded.
func startsClientHello(b64 string) bool {
	if len(b64) < 8 {
		return false
	}
	head, err := base64.StdEncoding.DecodeString(b64[:8])
	if err != nil || len(head) < 6 {
		return false
	}
	return head[0] == 0x16 && head[1] == 0x03 && head[5] == 0x01
}

// isHostName reports whether a lower-case name is dot-separated labels of
// letters, digits, hyphens and underscores, up to 253 bytes, with no empty
// label. Underscores are not in the host name rules, but names with them
// resolve and browsers send them (9 of 198,649 Tranco hosts).
func isHostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			if !hostByte(label[i]) {
				return false
			}
		}
	}
	return true
}

// hostByte is a byte a lower-case host name label may hold.
func hostByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// connectHost is a CONNECT's host name, lower case, without the port or a
// trailing dot.
func connectHost(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		h = hostport
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// Mismatch reports whether a TLS handshake names a server other than the
// CONNECT's host (hostport). The names are compared as written, so a name
// that is not a host name but is the CONNECT's own host is no mismatch. A
// handshake with no server name is none either.
func (h *Hello) Mismatch(hostport string) bool {
	return h.TLS && h.SNI != "" && h.SNI != connectHost(hostport)
}

// sniMismatchScore is under the block threshold: a server name other than
// the CONNECT's host blocks only with a second signal on that name (a
// generated or lookalike domain).
const sniMismatchScore = 5

// scanHello is the whole inspection of a CONNECT's second pass. The CONNECT
// line was inspected on the first pass; what is new is the server name. One
// that differs from the CONNECT's host is a signal, and that name gets the
// checks the host got: the SSRF rules and the domain reputation.
func (in *Inspection) scanHello(r *http.Request) {
	h := in.Hello
	if !h.TLS {
		return
	}
	if !h.Mismatch(r.Host) {
		return
	}
	if h.SNIInvalid {
		in.sniMismatch("server name is not a host name")
		return
	}
	in.sniMismatch(h.SNI)
	in.matchSegments(r, []string{h.SNI}, connectCategories)
	in.scanDomainReputation(h.SNI)
}

// sniMismatch adds the mismatch signal unless its category is switched off;
// the checks on the name itself keep their own switches.
func (in *Inspection) sniMismatch(pattern string) {
	if in.Eng.CategoryEnabled("TLS_SNI_MISMATCH") {
		in.Add(engine.MatchResult{RuleID: "TLS-SNI-001", Category: "TLS_SNI_MISMATCH", Pattern: pattern, Score: sniMismatchScore})
	}
}
