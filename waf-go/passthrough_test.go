package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"

	"github.com/go-icap/icap"

	"secure-proxy-waf/internal/engine"
)

// Squid sends "Allow: 204" only for a message it can keep a copy of. For a
// body of 64 KiB or more it leaves it out, and a 204 is then a protocol
// error: Squid answered the client 500, and after eleven such errors it
// suspended the ICAP service, which with REQMOD fail-closed refused every
// client for three minutes (measured on Squid 7.7). Without the header the
// WAF must return the message itself, whole.

// benignBody is prose, so the rule set has nothing to say about it.
func benignBody(n int) string {
	const prose = "The quarterly report covers deliveries, staffing and the new depot opening in spring. "
	return strings.Repeat(prose, n/len(prose)+1)[:n]
}

func reqmodNoAllow(t *testing.T, host string, body string) *mockResponseWriter {
	t.Helper()
	r := httptest.NewRequest("POST", "http://"+host+"/upload", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain")
	w := &mockResponseWriter{}
	handleReqmod(w, &icap.Request{Method: "REQMOD", Request: r, Header: textproto.MIMEHeader{"Allow": {"trailers"}}})
	return w
}

func TestReqmodWithoutAllow204ReturnsTheRequestWhole(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	// Around Squid's 64 KiB mark, and past the 1 MiB inspection limit,
	// where only a prefix is inspected but all of it has to be forwarded.
	for _, n := range []int{65536, 100000, maxBodyInspectSize + 4096} {
		body := benignBody(n)
		w := reqmodNoAllow(t, "upload.example.com", body)
		if w.code != 200 {
			t.Fatalf("%d bytes: ICAP %d, want 200 (a 204 is not allowed here)", n, w.code)
		}
		if _, ok := w.resp.(*http.Request); !ok {
			t.Fatalf("%d bytes: the 200 carries %T, want the original *http.Request", n, w.resp)
		}
		if w.body.String() != body {
			t.Errorf("%d bytes: forwarded %d bytes, not the original body", n, w.body.Len())
		}
	}
}

func TestReqmodWithAllow204StillAnswers204(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	r := httptest.NewRequest("POST", "http://upload.example.com/small", strings.NewReader(benignBody(2000)))
	r.Header.Set("Content-Type", "text/plain")
	w := &mockResponseWriter{}
	handleReqmod(w, &icap.Request{Method: "REQMOD", Request: r, Header: squidHeader()})
	if w.code != 204 || w.body.Len() != 0 {
		t.Errorf("ICAP %d with %d body bytes, want a bare 204", w.code, w.body.Len())
	}
}

func TestReqmodLANDestinationWithoutAllow204ReturnsTheRequest(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	body := benignBody(70000)
	w := reqmodNoAllow(t, "192.168.1.10", body)
	if _, ok := w.resp.(*http.Request); !ok || w.code != 200 || w.body.String() != body {
		t.Errorf("LAN destination: ICAP %d with %T and %d bytes, want 200 carrying the request whole", w.code, w.resp, w.body.Len())
	}
}

func TestRespmodWithoutAllow204ReturnsTheResponseWhole(t *testing.T) {
	withEngine(t, engine.Config{BlockThreshold: 10})
	body := benignBody(2*maxBodyInspectSize + 123)
	resp := &http.Response{
		StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"text/html"}},
		Body:   io.NopCloser(bytes.NewReader([]byte(body))),
	}
	w := &mockResponseWriter{}
	handleRespmod(w, &icap.Request{Method: "RESPMOD", Response: resp, Header: textproto.MIMEHeader{"Allow": {"trailers"}}})
	if w.code != 200 {
		t.Fatalf("ICAP %d, want 200", w.code)
	}
	if _, ok := w.resp.(*http.Response); !ok {
		t.Fatalf("the 200 carries %T, want the original *http.Response", w.resp)
	}
	if w.body.String() != body {
		t.Errorf("forwarded %d of %d response bytes", w.body.Len(), len(body))
	}

	// With the header, the same response is a 204.
	resp.Body = io.NopCloser(bytes.NewReader([]byte(body)))
	w = &mockResponseWriter{}
	handleRespmod(w, &icap.Request{Method: "RESPMOD", Response: resp, Header: squidHeader()})
	if w.code != 204 {
		t.Errorf("with Allow: 204, ICAP %d, want 204", w.code)
	}
}

func TestAllowsNoContent(t *testing.T) {
	for _, c := range []struct {
		allow []string
		want  bool
	}{
		{nil, false},
		{[]string{"trailers"}, false},
		{[]string{"204"}, true},
		{[]string{"204, trailers"}, true},
		{[]string{"trailers", "204"}, true},
		{[]string{"2040"}, false},
	} {
		req := &icap.Request{Header: textproto.MIMEHeader{}}
		for _, v := range c.allow {
			req.Header.Add("Allow", v)
		}
		if got := allowsNoContent(req); got != c.want {
			t.Errorf("Allow %q: got %v, want %v", c.allow, got, c.want)
		}
	}
}
