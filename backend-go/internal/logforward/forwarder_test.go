package logforward

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// fast shortens the forwarder's timers for one test.
func fast(t *testing.T) {
	t.Helper()
	r, b := ReloadEvery, backoffStart
	ReloadEvery, backoffStart = 50*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { ReloadEvery, backoffStart = r, b; rootCAs = nil })
}

// cfgBox is a configuration a test can change while the forwarder runs.
type cfgBox struct {
	mu sync.Mutex
	c  Config
}

func (b *cfgBox) load() Config { b.mu.Lock(); defer b.mu.Unlock(); return b.c }

func start(t *testing.T, c Config, capacity int) *Forwarder {
	t.Helper()
	box := &cfgBox{c: c}
	f := New(box.load, capacity)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	// Run has returned before fast puts the timers back.
	t.Cleanup(func() { cancel(); <-done })
	go func() { f.Run(ctx); close(done) }()
	return f
}

func entry(ip string, blocked int) map[string]any {
	return map[string]any{
		"unix_timestamp": int64(1794663900), "source_ip": ip, "method": "GET", "destination": "http://a.example/",
		"status": "TCP_MISS/200", "bytes": int64(512), "elapsed_ms": 12, "blocked": blocked, "reason": "none", "event_id": "",
	}
}

func port(t *testing.T, addr net.Addr) int {
	t.Helper()
	_, p, _ := net.SplitHostPort(addr.String())
	n, _ := strconv.Atoi(p)
	return n
}

// readOctetCounted reads one RFC 6587 octet-counted message.
func readOctetCounted(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	n, err := r.ReadString(' ')
	if err != nil {
		t.Fatalf("frame length: %v", err)
	}
	size, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil {
		t.Fatalf("frame length %q", n)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	return string(buf)
}

func acceptOne(t *testing.T, ln net.Listener) *bufio.Reader {
	t.Helper()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := ln.Accept(); ch <- res{c, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		t.Cleanup(func() { r.c.Close() })
		_ = r.c.SetReadDeadline(time.Now().Add(5 * time.Second))
		return bufio.NewReader(r.c)
	case <-time.After(5 * time.Second):
		t.Fatal("the forwarder never connected")
	}
	return nil
}

func TestForwarderSendsOverUDP(t *testing.T) {
	fast(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	f := start(t, Config{Enabled: true, Host: "127.0.0.1", Port: port(t, pc.LocalAddr()), Protocol: ProtoUDP,
		Format: FormatRFC5424, Events: EventsAll, Audit: true, Hostname: "spm-test"}, 100)
	f.Access(entry("192.168.1.20", 0))
	f.Audit("admin", "update_settings", "gdpr_mode", `{"from":"false","to":"true"}`)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 9000)
	var got []string
	for i := 0; i < 2; i++ {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		got = append(got, string(buf[:n]))
	}
	if !strings.HasPrefix(got[0], "<134>1 2026-11-14T13:45:00.000Z spm-test secure-proxy-manager - access - client=192.168.1.20 method=GET") {
		t.Errorf("access: %s", got[0])
	}
	if !strings.HasPrefix(got[1], "<133>1 ") || !strings.Contains(got[1], " - audit - user=admin action=update_settings target=gdpr_mode") {
		t.Errorf("audit: %s", got[1])
	}
}

func TestForwarderSendsOverTCPWithOctetCounting(t *testing.T) {
	fast(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f := start(t, Config{Enabled: true, Host: "127.0.0.1", Port: port(t, ln.Addr()), Protocol: ProtoTCP,
		Format: FormatRFC5424, Events: EventsAll}, 100)
	for i := 0; i < 3; i++ {
		f.Access(entry("10.0.0."+strconv.Itoa(i+1), 0))
	}
	r := acceptOne(t, ln)
	for i := 0; i < 3; i++ {
		if msg := readOctetCounted(t, r); !strings.Contains(msg, "client=10.0.0."+strconv.Itoa(i+1)+" ") {
			t.Errorf("message %d: %s", i, msg)
		}
	}
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "siem.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// TLS verifies the target: a certificate the roots do not trust is a
// connection that fails, and nothing is sent to it.
func TestForwarderSendsOverTLSOnlyToAVerifiedServer(t *testing.T) {
	fast(t)
	cert, pool := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c := Config{Enabled: true, Host: "127.0.0.1", Port: port(t, ln.Addr()), Protocol: ProtoTLS, Format: FormatJSON, Events: EventsAll}

	// Untrusted: the system roots do not know this certificate.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.(*tls.Conn).Handshake()
		conn.Close()
	}()
	if err := SendTest(context.Background(), c); err == nil {
		t.Fatal("a certificate no root trusts was accepted")
	}

	rootCAs = pool
	f := start(t, c, 100)
	f.Access(entry("192.168.1.30", 1))
	r := acceptOne(t, ln)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `"client":"192.168.1.30"`) || !strings.Contains(line, `"severity":"warning"`) {
		t.Errorf("line: %s", line)
	}
}

// Only blocked requests when asked, client addresses masked in GDPR mode,
// and audit events only when they are switched on.
func TestWhatIsSentFollowsTheSettings(t *testing.T) {
	fast(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	f := start(t, Config{Enabled: true, Host: "127.0.0.1", Port: port(t, pc.LocalAddr()), Protocol: ProtoUDP,
		Format: FormatJSON, Events: EventsBlocked, Audit: false, MaskIPs: true}, 100)
	f.Access(entry("192.168.1.40", 0))
	f.Audit("admin", "login", "", "")
	f.Access(entry("192.168.1.41", 1))
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 9000)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, `"blocked":"true"`) || strings.Contains(got, "192.168.1.41") || !strings.Contains(got, `"client":"192.168.1.x"`) {
		t.Errorf("first event: %s", got)
	}
	_ = pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := pc.ReadFrom(buf); err == nil {
		t.Errorf("a second event was sent: %s", buf[:n])
	}
}

// A queue that is full drops new events and counts them, without waiting.
func TestAFullQueueDropsAndCounts(t *testing.T) {
	fast(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	p := port(t, ln.Addr())
	ln.Close() // nobody listens: the forwarder cannot connect, the queue fills
	f := start(t, Config{Enabled: true, Host: "127.0.0.1", Port: p, Protocol: ProtoTCP, Format: FormatRFC5424, Events: EventsAll}, 3)
	before := metrics.LogForwardCount(metrics.LogForwardDropped)
	t0 := time.Now()
	for i := 0; i < 10; i++ {
		f.Access(entry("10.1.1.1", 0))
	}
	if d := time.Since(t0); d > 100*time.Millisecond {
		t.Errorf("10 events took %v: queuing must not wait", d)
	}
	if got := metrics.LogForwardCount(metrics.LogForwardDropped) - before; got != 7 {
		t.Errorf("%v dropped, want 7", got)
	}
}

// Events queued while the target is down go once it is back.
func TestEventsWaitForATargetThatComesBack(t *testing.T) {
	fast(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	p := port(t, ln.Addr())
	ln.Close()
	f := start(t, Config{Enabled: true, Host: "127.0.0.1", Port: p, Protocol: ProtoTCP, Format: FormatRFC5424, Events: EventsAll}, 100)
	for i := 0; i < 3; i++ {
		f.Access(entry("10.2.2."+strconv.Itoa(i+1), 0))
	}
	time.Sleep(300 * time.Millisecond)
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
	if err != nil {
		t.Skipf("the port was taken meanwhile: %v", err)
	}
	defer ln.Close()
	r := acceptOne(t, ln)
	for i := 0; i < 3; i++ {
		if msg := readOctetCounted(t, r); !strings.Contains(msg, "client=10.2.2."+strconv.Itoa(i+1)+" ") {
			t.Errorf("message %d: %s", i, msg)
		}
	}
}

// Switched off, nothing is queued at all.
func TestNothingIsQueuedWhenOff(t *testing.T) {
	f := New(func() Config { return Config{Enabled: false, Events: EventsAll, Audit: true} }, 5)
	f.Access(entry("10.3.3.3", 1))
	f.Audit("admin", "x", "", "")
	if len(f.queue) != 0 {
		t.Errorf("%d events queued while off", len(f.queue))
	}
}

// A target that closes the connection (a restart of the syslog server) is
// noticed before the next write: the events after it go on a new
// connection, none is written into the closed one and lost.
func TestAClosedTargetIsReconnectedWithoutLosingEvents(t *testing.T) {
	fast(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f := start(t, Config{Enabled: true, Host: "127.0.0.1", Port: port(t, ln.Addr()), Protocol: ProtoTCP, Format: FormatRFC5424, Events: EventsAll}, 100)
	f.Access(entry("10.4.4.1", 0))
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if msg := readOctetCounted(t, bufio.NewReader(conn)); !strings.Contains(msg, "client=10.4.4.1 ") {
		t.Fatalf("first: %s", msg)
	}
	conn.Close()
	time.Sleep(200 * time.Millisecond)
	f.Access(entry("10.4.4.2", 0))
	f.Access(entry("10.4.4.3", 0))
	r := acceptOne(t, ln)
	for _, want := range []string{"10.4.4.2", "10.4.4.3"} {
		if msg := readOctetCounted(t, r); !strings.Contains(msg, "client="+want+" ") {
			t.Errorf("want %s, got %s", want, msg)
		}
	}
}
