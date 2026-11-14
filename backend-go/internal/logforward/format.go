// Package logforward sends the proxy's access log and the admin audit log to
// a syslog server or a SIEM, as RFC 5424 syslog or as JSON lines, over UDP,
// TCP or TLS.
//
// Events wait in a bounded queue; when the target is slow or down the queue
// fills and new events are dropped and counted, so forwarding never holds up
// the log ingestion that feeds it.
package logforward

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// The protocols and formats a target can use.
const (
	ProtoUDP = "udp"
	ProtoTCP = "tcp"
	ProtoTLS = "tls"

	FormatRFC5424 = "rfc5424"
	FormatJSON    = "json"

	// Which access log rows are sent.
	EventsAll     = "all"
	EventsBlocked = "blocked"
	EventsNone    = "none"
)

// The kinds of event.
const (
	KindAccess = "access"
	KindAudit  = "audit"
	KindTest   = "test"
)

// Syslog severities (RFC 5424 section 6.2.1) the events use.
const (
	SevWarning = 4
	SevNotice  = 5
	SevInfo    = 6
)

// facilityLocal0 is the facility every message carries: local0 (16).
const facilityLocal0 = 16

// AppName is the APP-NAME of every message and the "app" of every JSON line.
const AppName = "secure-proxy-manager"

// maxMessage bounds one message. A UDP datagram over this is cut by most
// receivers anyway; the bound also keeps a long URL from making one event
// unbounded.
const maxMessage = 8192

// Field is one key and value of an event, kept in order so every message of
// a kind lists its fields the same way.
type Field struct {
	Key   string
	Value string
}

// Event is one thing to send.
type Event struct {
	Time     time.Time
	Kind     string
	Severity int
	Fields   []Field
}

// Format writes e as one message in format, without transport framing.
// hostname is the HOSTNAME of a syslog message and "host" of a JSON line.
func Format(format, hostname string, e Event) []byte {
	var out []byte
	if format == FormatJSON {
		out = formatJSON(hostname, e)
	} else {
		out = formatRFC5424(hostname, e)
	}
	if len(out) > maxMessage {
		out = out[:maxMessage]
	}
	return out
}

// formatRFC5424 is "<PRI>1 TIMESTAMP HOSTNAME APP-NAME - MSGID - MSG": no
// PROCID and no structured data (an SD-ID of our own would need an IANA
// enterprise number), and the fields as key=value pairs in MSG, which syslog
// servers and SIEMs parse without configuration.
func formatRFC5424(hostname string, e Event) []byte {
	var b strings.Builder
	b.WriteString("<")
	b.WriteString(strconv.Itoa(facilityLocal0*8 + e.Severity))
	b.WriteString(">1 ")
	b.WriteString(e.Time.UTC().Format("2006-01-02T15:04:05.000Z"))
	b.WriteString(" ")
	b.WriteString(headerField(hostname, 255))
	b.WriteString(" ")
	b.WriteString(AppName)
	b.WriteString(" - ")
	b.WriteString(headerField(e.Kind, 32))
	b.WriteString(" - ")
	for i, f := range e.Fields {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(f.Key)
		b.WriteString("=")
		b.WriteString(logfmtValue(f.Value))
	}
	return []byte(b.String())
}

// headerField is a header field as RFC 5424 allows it: printable US-ASCII
// without spaces, at most max characters, "-" when empty.
func headerField(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r > 32 && r < 127 {
			b.WriteRune(r)
		}
		if b.Len() >= max {
			break
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// logfmtValue writes a value so a receiver reads it back whole: control
// characters (a newline would start a forged second event) become spaces,
// and a value with a space, a quote or an equals sign is quoted.
func logfmtValue(v string) string {
	clean := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, v)
	if clean == "" {
		return `""`
	}
	if strings.ContainsAny(clean, " \"=\\") {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(clean) + `"`
	}
	return clean
}

// formatJSON is one JSON object: time, host, app, kind, severity and the
// fields. encoding/json escapes control characters, so a value cannot break
// the line.
func formatJSON(hostname string, e Event) []byte {
	m := make(map[string]any, len(e.Fields)+5)
	for _, f := range e.Fields {
		m[f.Key] = f.Value
	}
	m["time"] = e.Time.UTC().Format(time.RFC3339Nano)
	m["host"] = hostname
	m["app"] = AppName
	m["kind"] = e.Kind
	m["severity"] = severityName(e.Severity)
	out, err := json.Marshal(m)
	if err != nil {
		return []byte(`{"app":"` + AppName + `","error":"unencodable event"}`)
	}
	return out
}

func severityName(s int) string {
	switch s {
	case SevWarning:
		return "warning"
	case SevNotice:
		return "notice"
	default:
		return "info"
	}
}

// frame wraps a message for the transport: a UDP datagram carries it as it
// is; on TCP and TLS a syslog message is prefixed with its length (octet
// counting, RFC 6587 section 3.4.1, which RFC 5425 requires for TLS) and a
// JSON line ends with a newline.
func frame(proto, format string, msg []byte) []byte {
	if proto == ProtoUDP {
		return msg
	}
	if format == FormatJSON {
		return append(append([]byte{}, msg...), '\n')
	}
	return append([]byte(strconv.Itoa(len(msg))+" "), msg...)
}
