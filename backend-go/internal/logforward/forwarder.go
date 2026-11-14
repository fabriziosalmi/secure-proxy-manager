package logforward

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/privacy"
)

// Config is where events go and which ones. The forwarder reads it from the
// settings (settings.go in handlers) every ReloadEvery.
type Config struct {
	Enabled  bool
	Host     string
	Port     int
	Protocol string // ProtoUDP, ProtoTCP, ProtoTLS
	Format   string // FormatRFC5424, FormatJSON
	Events   string // EventsAll, EventsBlocked, EventsNone: the access log rows sent
	Audit    bool   // whether admin audit events are sent
	Hostname string // the HOSTNAME sent; AppName when empty
	MaskIPs  bool   // gdpr_mode: client addresses leave masked, as from the API
}

// Addr is host:port.
func (c Config) Addr() string { return net.JoinHostPort(c.Host, strconv.Itoa(c.Port)) }

func (c Config) sameTarget(o Config) bool {
	return c.Host == o.Host && c.Port == o.Port && c.Protocol == o.Protocol
}

func (c Config) hostname() string {
	if c.Hostname != "" {
		return c.Hostname
	}
	return AppName
}

// The forwarder's timing. Variables so a test can shorten them.
var (
	// ReloadEvery is how often the settings are read again.
	ReloadEvery = 10 * time.Second
	dialTimeout = 5 * time.Second
	// writeTimeout bounds one write: a TCP target that stops reading must not
	// hold the queue forever.
	writeTimeout = 5 * time.Second
	// backoffStart is the first wait after a failed connection attempt, and
	// backoffMax caps the wait as it doubles.
	backoffStart = time.Second
	backoffMax   = time.Minute
	// rootCAs verifies a TLS target; nil is the system's roots. A test sets it.
	rootCAs *x509.CertPool
)

// QueueCapacity is how many events wait for a slow or unreachable target
// before new ones are dropped: about a minute of a busy proxy.
const QueueCapacity = 10000

// Forwarder sends events to the configured target from one goroutine (Run).
type Forwarder struct {
	load  func() Config
	queue chan Event
	cfg   atomic.Pointer[Config]
	dial  func(ctx context.Context, c Config) (net.Conn, error)
}

// New returns a forwarder that reads its configuration with load.
func New(load func() Config, capacity int) *Forwarder {
	f := &Forwarder{load: load, queue: make(chan Event, capacity), dial: Dial}
	f.reload()
	return f
}

func (f *Forwarder) reload() Config {
	c := f.load()
	f.cfg.Store(&c)
	return c
}

// Config is the configuration in force.
func (f *Forwarder) Config() Config { return *f.cfg.Load() }

// Dial connects to c's target: UDP, TCP, or TLS with the system's roots and
// the host as server name.
func Dial(ctx context.Context, c Config) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	switch c.Protocol {
	case ProtoUDP:
		return d.DialContext(ctx, "udp", c.Addr())
	case ProtoTCP:
		return d.DialContext(ctx, "tcp", c.Addr())
	case ProtoTLS:
		td := tls.Dialer{NetDialer: &d, Config: &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12, RootCAs: rootCAs}}
		return td.DialContext(ctx, "tcp", c.Addr())
	}
	return nil, fmt.Errorf("unknown protocol %q", c.Protocol)
}

// enqueue adds e without waiting: a full queue drops it and counts it.
func (f *Forwarder) enqueue(e Event) {
	select {
	case f.queue <- e:
	default:
		metrics.LogForward(metrics.LogForwardDropped)
	}
}

// Access queues one parsed access log row (workers/log_tailer.go) when the
// configuration sends it.
func (f *Forwarder) Access(entry map[string]any) {
	c := f.Config()
	if !c.Enabled || c.Events == EventsNone || c.Events == "" {
		return
	}
	blocked := entry["blocked"] == 1
	if c.Events == EventsBlocked && !blocked {
		return
	}
	client := str(entry["source_ip"])
	if c.MaskIPs {
		client = privacy.MaskIP(client)
	}
	t := time.Now()
	if ts, ok := entry["unix_timestamp"].(int64); ok && ts > 0 {
		t = time.Unix(ts, 0)
	}
	sev := SevInfo
	if blocked {
		sev = SevWarning
	}
	fields := []Field{
		{"client", client},
		{"method", str(entry["method"])},
		{"destination", str(entry["destination"])},
		{"status", str(entry["status"])},
		{"bytes", str(entry["bytes"])},
		{"elapsed_ms", str(entry["elapsed_ms"])},
		{"blocked", strconv.FormatBool(blocked)},
		{"reason", str(entry["reason"])},
	}
	if id := str(entry["event_id"]); id != "" {
		fields = append(fields, Field{"event_id", id})
	}
	f.enqueue(Event{Time: t, Kind: KindAccess, Severity: sev, Fields: fields})
}

// Audit queues one admin audit event (database.Audit) when the
// configuration sends them.
func (f *Forwarder) Audit(username, action, target, details string) {
	c := f.Config()
	if !c.Enabled || !c.Audit {
		return
	}
	f.enqueue(Event{Time: time.Now(), Kind: KindAudit, Severity: SevNotice, Fields: []Field{
		{"user", username}, {"action", action}, {"target", target}, {"details", details},
	}})
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// Run sends queued events until ctx ends. While the target cannot be reached
// it waits, with a growing pause between attempts, and leaves the events in
// the queue; they go once it connects. An event whose write fails is counted
// as failed and the connection is made again.
func (f *Forwarder) Run(ctx context.Context) {
	// The timing as it is when Run starts: one value for the life of the loop.
	reloadEvery, firstBackoff, maxBackoff := ReloadEvery, backoffStart, backoffMax
	ticker := time.NewTicker(reloadEvery)
	defer ticker.Stop()
	var conn net.Conn
	var connCfg Config
	var nextDial time.Time
	backoff := firstBackoff
	closeConn := func() {
		if conn != nil {
			conn.Close() //nolint:errcheck // a failed close changes nothing here
			conn = nil
			metrics.LogForwardConnected(false)
		}
	}
	defer closeConn()
	for {
		c := f.Config()
		if c.Enabled && conn == nil && !time.Now().Before(nextDial) {
			nc, err := f.dial(ctx, c)
			if err != nil {
				log.Warn().Err(err).Str("target", c.Addr()).Str("protocol", c.Protocol).Msg("log forwarding: cannot connect")
				metrics.LogForward(metrics.LogForwardConnectFailed)
				nextDial = time.Now().Add(backoff)
				backoff = min(backoff*2, maxBackoff)
			} else {
				conn, connCfg, backoff = nc, c, firstBackoff
				metrics.LogForwardConnected(true)
			}
		}
		// Take an event only when it can be written, or when forwarding is
		// off (the queue is then emptied, the events counted as dropped).
		var q <-chan Event
		if conn != nil || !c.Enabled {
			q = f.queue
		}
		var wait <-chan time.Time
		if c.Enabled && conn == nil {
			wait = time.After(time.Until(nextDial))
		}
		metrics.LogForwardQueue(len(f.queue))
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if nc := f.reload(); conn != nil && (!nc.Enabled || !nc.sameTarget(connCfg)) {
				closeConn()
				nextDial = time.Time{}
			}
		case <-wait:
		case e := <-q:
			if !c.Enabled {
				metrics.LogForward(metrics.LogForwardDropped)
				continue
			}
			msg := frame(connCfg.Protocol, c.Format, Format(c.Format, c.hostname(), e))
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, err := conn.Write(msg); err != nil {
				log.Warn().Err(err).Str("target", connCfg.Addr()).Msg("log forwarding: write failed, reconnecting")
				metrics.LogForward(metrics.LogForwardFailed)
				closeConn()
				nextDial = time.Now().Add(backoff)
				continue
			}
			metrics.LogForward(metrics.LogForwardSent)
		}
	}
}

// SendTest sends one test event to c's target now, outside the queue, and
// says whether it went: on TCP and TLS the connection and the write
// succeeded; on UDP only that the datagram left, since UDP has no answer.
func SendTest(ctx context.Context, c Config) error {
	conn, err := Dial(ctx, c)
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck
	e := Event{Time: time.Now(), Kind: KindTest, Severity: SevNotice, Fields: []Field{
		{"message", "test event from Secure Proxy Manager"},
	}}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err = conn.Write(frame(c.Protocol, c.Format, Format(c.Format, c.hostname(), e)))
	return err
}

// The forwarder the log tailer and the audit log feed, set once at start.
var defaultForwarder atomic.Pointer[Forwarder]

// SetDefault makes f the forwarder Access and Audit feed.
func SetDefault(f *Forwarder) { defaultForwarder.Store(f) }

// Access queues an access log row on the default forwarder, if there is one.
func Access(entry map[string]any) {
	if f := defaultForwarder.Load(); f != nil {
		f.Access(entry)
	}
}

// Audit queues an audit event on the default forwarder, if there is one.
func Audit(username, action, target, details string) {
	if f := defaultForwarder.Load(); f != nil {
		f.Audit(username, action, target, details)
	}
}
