package inspect

// Values sent as base64 (W.3.2b). A path traversal or a file inclusion
// written in base64 ("Li4vLi4vZXRjL3Bhc3N3ZA==" is "../../etc/passwd")
// reaches an application that decodes the parameter with nothing for the
// rules to read. Each base64 token of the URL and of the body is decoded
// and matched, normalized, against the categories in base64Categories only.
//
// Only those categories read it: a decoded token is often a word, a name,
// JSON (a JWT's header and claims) or bytes, where the injection rules would
// find what is not there, while "../", "php://" or a command chain in a
// decoded value is an attack in base64 or nothing. What a token decodes to
// is not checked further: a control byte or a NUL after the path
// ("../../etc/passwd\x00") must not make it skip the rules.
// Headers are left out: cookies, Authorization and the tracing headers carry
// base64 on every request.

import (
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"

	"secure-proxy-waf/internal/engine"
)

// base64Categories are the categories that read a decoded value, less
// CMDi-003 and CMDi-004: "$(...)" and two backticks are a few bytes, which
// the bytes of an image or a protobuf sent as base64 hold by chance (on
// 258,465 Tranco requests they blocked 41 with nothing else to go on). The
// rules left read a structure as long as "; cat " or "../../".
var base64Categories = map[string]bool{
	"DIRECTORY_TRAVERSAL": true, "PATH_MANIPULATION": true, "COMMAND_INJECTION": true,
	"CMDi-003": false, "CMDi-004": false,
}

// minBase64Token is the shortest token decoded: "Li4vLi4v" is "../../".
// There is no upper bound and no count: a payload after spaces, or after
// as many decoy tokens as it takes, would get past one. The body is already
// cut at MaxBodyInspectSize, and only base64Categories read what decodes.
const minBase64Token = 8

// base64Token is a run of the standard or URL-safe alphabet, padding
// included, between two characters outside it.
var base64Token = regexp.MustCompile(`[A-Za-z0-9+/_-]{8,}={0,2}`)

// base64Decoded returns what the base64 tokens in texts decode to.
func base64Decoded(texts []string) []string {
	var out []string
	for _, t := range texts {
		for _, tok := range base64Token.FindAllString(t, -1) {
			if s, ok := decodeBase64(tok); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// decodeBase64 decodes tok in the alphabet it is written in, padded or not.
func decodeBase64(tok string) (string, bool) {
	raw := strings.TrimRight(tok, "=")
	if len(raw) < minBase64Token || len(raw)%4 == 1 {
		return "", false
	}
	enc := base64.RawStdEncoding
	if strings.ContainsAny(raw, "-_") {
		if strings.ContainsAny(raw, "+/") {
			return "", false
		}
		enc = base64.RawURLEncoding
	}
	b, err := enc.DecodeString(raw)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// matchBase64 matches what is decoded from the base64 tokens of
// texts against base64Categories.
func (in *Inspection) matchBase64(r *http.Request, texts []string) {
	decoded := base64Decoded(texts)
	if len(decoded) == 0 {
		return
	}
	for i, s := range decoded {
		decoded[i] = engine.NormalizeInput(s)
	}
	in.matchSegments(r, decoded, base64Categories)
}
