package inspect

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var benchWords = strings.Fields("the order was shipped on monday and the invoice number is attached please review the account settings before the next meeting with the team about quarterly results revenue growth customer feedback product roadmap release notes version update support ticket resolved escalation pending approval budget forecast")

func benignBody(kind string, n int) (string, string) {
	r := rand.New(rand.NewSource(1))
	var b strings.Builder
	switch kind {
	case "text":
		for b.Len() < n {
			b.WriteString(benchWords[r.Intn(len(benchWords))])
			if r.Intn(12) == 0 {
				b.WriteString(".\n")
			} else {
				b.WriteByte(' ')
			}
		}
		return "text/plain", b.String()[:n]
	case "form":
		for i := 0; b.Len() < n; i++ {
			if i > 0 {
				b.WriteByte('&')
			}
			fmt.Fprintf(&b, "field%d=%s+%s+%d", i, benchWords[r.Intn(len(benchWords))], benchWords[r.Intn(len(benchWords))], r.Intn(100000))
		}
		return "application/x-www-form-urlencoded", b.String()[:n]
	default:
		b.WriteString(`{"items":[`)
		for i := 0; b.Len() < n-40; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"id":%d,"name":"%s %s","qty":%d,"note":"%s"}`, i, benchWords[r.Intn(len(benchWords))], benchWords[r.Intn(len(benchWords))], r.Intn(50), benchWords[r.Intn(len(benchWords))])
		}
		b.WriteString(`]}`)
		return "application/json", b.String()
	}
}

// BenchmarkBody times Evaluate on benign POST bodies by engine, type and
// size, the cost a request pays for the WAF reading its body.
func BenchmarkBody(b *testing.B) {
	for _, engine := range []string{"legacy", "hybrid"} {
		for _, kind := range []string{"text", "form", "json"} {
			for _, size := range []int{4 << 10, 64 << 10, 1 << 20} {
				ct, body := benignBody(kind, size)
				b.Run(fmt.Sprintf("%s/%s/%dKiB", engine, kind, size>>10), func(b *testing.B) {
					c := crsPL1
					if engine == "legacy" {
						c = nil
					}
					eng := newEngine()
					b.SetBytes(int64(len(body)))
					for b.Loop() {
						r := httptest.NewRequest(http.MethodPost, "http://shop.example/api/upload", strings.NewReader(body))
						r.Header.Set("Content-Type", ct)
						Evaluate(eng, c, nil, r, "192.0.2.50")
					}
				})
			}
		}
	}
}
