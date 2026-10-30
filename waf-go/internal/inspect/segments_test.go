package inspect

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBodySegments(t *testing.T) {
	for _, c := range []struct {
		name, ct, body string
		want           []string
		ok             bool
	}{
		{"form", "application/x-www-form-urlencoded", "a=1&b=x%26y&&c=", []string{"a=1", "b=x%26y", "c="}, true},
		{"json leaves and container keys", "application/json; charset=utf-8",
			`{"user":{"name":"ann","tags":["a",1,true,null]},"__proto__":{"x":"y"},"n":2.5}`,
			[]string{"user=", "name=ann", "tags=", "tags=a", "tags=1", "tags=true", "tags=null", "__proto__=", "x=y", "n=2.5"}, true},
		{"json top-level array", "application/vnd.api+json", `[{"q":"x"},"y"]`, []string{"q=x", "=y"}, true},
		{"json broken", "application/json", `{"a":`, nil, false},
		{"json two documents", "application/json", `{"a":1} {"b":2}`, nil, false},
		{"json too deep", "application/json", strings.Repeat("[", maxJSONDepth+1) + strings.Repeat("]", maxJSONDepth+1), nil, false},
		{"text", "text/plain", "a=1", nil, false},
		{"xml", "application/xml", "<a/>", nil, false},
	} {
		got, ok := bodySegments(c.ct, []byte(c.body))
		if ok != c.ok || strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: %v %q, want %v %q", c.name, ok, got, c.ok, c.want)
		}
	}
	body := "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php system($_GET['c']); ?>\r\n--B--\r\n"
	got, ok := bodySegments("multipart/form-data; boundary=B", []byte(body))
	if !ok || len(got) != 2 || !strings.Contains(got[0], `filename="shell.php"`) || got[1] != "f=<?php system($_GET['c']); ?>" {
		t.Errorf("multipart: %v %q", ok, got)
	}
}

func postBody(t *testing.T, ct, body string) *Inspection {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://shop.example/api", strings.NewReader(body))
	r.Header.Set("Content-Type", ct)
	in, _ := Evaluate(newEngine(), nil, nil, r, "192.0.2.60")
	return in
}

// A benign JSON body is no longer matched across its fields: the 600 KiB
// document that SQLi-003 and SSRF-007 blocked as one string passes. An
// attack inside one value still blocks, in JSON, in a form and in a
// multipart upload.
func TestArgumentsAreMatchedOneByOne(t *testing.T) {
	ct, body := benignBody("json", 600<<10)
	if in := postBody(t, ct, body); in.Blocked() {
		t.Errorf("benign JSON blocked: %s", ids(in))
	}
	for _, c := range []struct{ ct, body string }{
		{"application/json", `{"q":"x","id":"1' UNION SELECT password FROM users--"}`},
		{"application/x-www-form-urlencoded", "q=x&id=1%27%20UNION%20SELECT%20password%20FROM%20users--"},
		{"multipart/form-data; boundary=B", "--B\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\n<script>alert(document.cookie)</script>\r\n--B--\r\n"},
		{"application/json", `{"__proto__":{"isAdmin":true}}`},
	} {
		if in := postBody(t, c.ct, c.body); !in.Blocked() {
			t.Errorf("%s %q not blocked: %s", c.ct, c.body, ids(in))
		}
	}
	// A body that does not parse is matched whole, as before.
	if in := postBody(t, "application/json", `{"id":"1' UNION SELECT password FROM users--"`); !in.Blocked() {
		t.Errorf("broken JSON with an attack not blocked: %s", ids(in))
	}
}

// The URL and each header value are matched one by one: a pattern no longer
// runs from one header into the next. Joined and compacted, Accept's */* and
// a next header's value made SQLi-003 read UPDATE ... SET here; one header
// holding it whole still matches.
func TestHeadersAreMatchedOneByOne(t *testing.T) {
	get := func(h map[string]string) *Inspection {
		r := httptest.NewRequest(http.MethodGet, "http://shop.example/", nil)
		for k, v := range h {
			r.Header.Set(k, v)
		}
		in, _ := Evaluate(newEngine(), nil, nil, r, "192.0.2.61")
		return in
	}
	if in := get(map[string]string{"X-A": "please update", "X-B": "users set password=1"}); strings.Contains(ids(in), "SQLi-003") {
		t.Errorf("a pattern ran across two headers: %s", ids(in))
	}
	if in := get(map[string]string{"X-A": "update users set password=1"}); !strings.Contains(ids(in), "SQLi-003") {
		t.Errorf("one header with the whole statement: %s", ids(in))
	}
}
