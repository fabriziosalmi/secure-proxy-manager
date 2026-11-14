package logforward

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 11, 14, 13, 45, 0, 123e6, time.UTC)

func accessEvent() Event {
	return Event{Time: at, Kind: KindAccess, Severity: SevWarning, Fields: []Field{
		{"client", "192.168.1.20"}, {"method", "GET"}, {"destination", "http://a.example/x?q=1 2"},
		{"status", "TCP_MISS/403"}, {"bytes", "205"}, {"blocked", "true"}, {"reason", "waf"},
	}}
}

// The syslog line is the RFC 5424 header (facility local0, severity warning:
// PRI 132), no PROCID and no structured data, then key=value pairs with a
// value quoted when it holds a space, a quote or an equals sign.
func TestRFC5424Line(t *testing.T) {
	got := string(Format(FormatRFC5424, "spm-1", accessEvent()))
	want := `<132>1 2026-11-14T13:45:00.123Z spm-1 secure-proxy-manager - access - client=192.168.1.20 method=GET destination="http://a.example/x?q=1 2" status=TCP_MISS/403 bytes=205 blocked=true reason=waf`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

// A value cannot start a second event: control characters become spaces, a
// quote is escaped, and an empty host is "-".
func TestRFC5424ValueCannotForgeALine(t *testing.T) {
	e := Event{Time: at, Kind: KindAudit, Severity: SevNotice, Fields: []Field{
		{"details", "ok\n<132>1 2026-11-14T00:00:00Z evil app - access - forged=1"}, {"target", `say "hi"`}, {"user", ""},
	}}
	got := string(Format(FormatRFC5424, "", e))
	if strings.ContainsAny(got, "\n\r") {
		t.Fatalf("a newline survived: %q", got)
	}
	for _, part := range []string{`<133>1 `, ` secure-proxy-manager - audit - `, `details="ok <132>1 2026-11-14T00:00:00Z evil app - access - forged=1"`, `target="say \"hi\""`, `user=""`} {
		if !strings.Contains(got, part) {
			t.Errorf("missing %q in %q", part, got)
		}
	}
	if !strings.Contains(got, `2026-11-14T13:45:00.123Z - secure-proxy-manager`) {
		t.Errorf("an empty hostname must be \"-\": %q", got)
	}
}

func TestJSONLine(t *testing.T) {
	e := accessEvent()
	e.Fields = append(e.Fields, Field{"details", "a\nb"})
	got := Format(FormatJSON, "spm-1", e)
	if strings.Contains(string(got), "\n") {
		t.Fatalf("a raw newline in %q", got)
	}
	var m map[string]string
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"time": "2026-11-14T13:45:00.123Z", "host": "spm-1", "app": AppName, "kind": "access", "severity": "warning",
		"client": "192.168.1.20", "destination": "http://a.example/x?q=1 2", "details": "a\nb",
	} {
		if m[k] != v {
			t.Errorf("%s = %q, want %q", k, m[k], v)
		}
	}
}

// UDP carries the message as it is; TCP and TLS prefix a syslog message with
// its length (RFC 6587 octet counting) and end a JSON line with a newline.
func TestFraming(t *testing.T) {
	msg := []byte("<134>1 x")
	if string(frame(ProtoUDP, FormatRFC5424, msg)) != "<134>1 x" {
		t.Error("udp")
	}
	if string(frame(ProtoTCP, FormatRFC5424, msg)) != "8 <134>1 x" {
		t.Errorf("tcp: %q", frame(ProtoTCP, FormatRFC5424, msg))
	}
	if string(frame(ProtoTLS, FormatJSON, []byte(`{}`))) != "{}\n" {
		t.Error("tls json")
	}
}

func TestAMessageIsBounded(t *testing.T) {
	e := accessEvent()
	e.Fields = append(e.Fields, Field{"destination", strings.Repeat("a", 20000)})
	if n := len(Format(FormatRFC5424, "h", e)); n != maxMessage {
		t.Errorf("%d bytes, want %d", n, maxMessage)
	}
}
