// Package sources decides whether a source address in the access log is a
// device on the user's network or a part of this deployment.
//
// The proxy logs every connection it serves, including the ones the stack
// makes itself: the backend fetching through the proxy, a request made on the
// Docker host (published ports reach the proxy from the bridge gateway), and
// loopback inside the proxy container. Counted as clients, they showed up on
// the Overview as "Active clients" and in the client list as devices.
//
// An address is internal when it is loopback, or when it falls inside a
// subnet of the backend container's own network interfaces. In the shipped
// compose files the backend and the proxy share both of their networks
// (frontend and proxy-internal), so those subnets are the ones the proxy sees
// the stack's own traffic come from. No range is hard-coded: a LAN can be
// 172.16.0.0/12 too, and only the subnets this container is attached to are
// internal.
//
// The interface subnets are used only when the proxy resolves to an address
// inside one of them, the evidence that the backend sits on the proxy's
// container network. Run on a host (PROXY_HOST=localhost) the backend's
// interfaces are the LAN's, and treating them as internal would hide every
// device; in that case only loopback is internal.
package sources

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Kinds, written for the client list. Each says only what the classifier
// knows: an address in a stack subnet that is not the backend, the proxy or
// the gateway is "another address on this stack's network", not a named
// service.
const (
	KindLoopback = "Internal: loopback, from inside the proxy container"
	KindBackend  = "Internal: the backend"
	KindProxy    = "Internal: the proxy"
	KindHost     = "Internal: this host"
	KindStack    = "Internal: another address on this stack's network"
	KindPrivate  = "Private network address"
	KindPublic   = "Public address"
)

// Snapshot is what the classifier knows about this deployment.
type Snapshot struct {
	// Subnets of the backend's interfaces, when it shares them with the proxy.
	Subnets []netip.Prefix
	// Self: the backend's own addresses on those subnets.
	Self []netip.Addr
	// Proxy: the proxy's addresses on those subnets.
	Proxy []netip.Addr
	// Gateways: the default gateway, the Docker host's side of the bridge,
	// when it is on one of those subnets.
	Gateways []netip.Addr
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// NewSnapshot builds a snapshot from the backend's interface addresses, the
// addresses PROXY_HOST resolved to and the contents of /proc/net/route.
func NewSnapshot(ifaceAddrs []net.Addr, proxy []netip.Addr, route []byte) Snapshot {
	var subnets []netip.Prefix
	var self []netip.Addr
	for _, a := range ifaceAddrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
			continue
		}
		ones, _ := ipn.Mask.Size()
		if addr.Is4() && ones > 32 {
			ones -= 96
		}
		p, err := addr.Prefix(ones)
		if err != nil {
			continue
		}
		self = append(self, addr)
		if !slices.Contains(subnets, p) {
			subnets = append(subnets, p)
		}
	}
	var s Snapshot
	for _, p := range proxy {
		p = p.Unmap()
		if inAny(subnets, p) {
			s.Proxy = append(s.Proxy, p)
		}
	}
	if len(s.Proxy) == 0 {
		// Not on the proxy's network: only loopback is internal.
		return Snapshot{}
	}
	s.Subnets, s.Self = subnets, self
	for _, g := range defaultGateways(route) {
		if inAny(subnets, g) {
			s.Gateways = append(s.Gateways, g)
		}
	}
	return s
}

func inAny(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// defaultGateways reads the gateways of the default routes in /proc/net/route
// (IPv4 only; the file has no IPv6 routes). Addresses there are hex in host
// byte order, little-endian on every platform the image is built for.
func defaultGateways(route []byte) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(bytes.NewReader(route))
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x2 == 0 { // RTF_GATEWAY
			continue
		}
		b, err := hex.DecodeString(f[2])
		if err != nil || len(b) != 4 {
			continue
		}
		g := netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]})
		if !g.IsUnspecified() && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}

// Classify says whether ip is internal and, where it can be said, what it is.
func (s Snapshot) Classify(ip string) (internal bool, kind string) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false, ""
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return true, KindLoopback
	case slices.Contains(s.Self, a):
		return true, KindBackend
	case slices.Contains(s.Proxy, a):
		return true, KindProxy
	case slices.Contains(s.Gateways, a):
		return true, KindHost
	case inAny(s.Subnets, a):
		return true, KindStack
	case a.IsPrivate():
		return false, KindPrivate
	case a.IsGlobalUnicast() && !cgnat.Contains(a):
		return false, KindPublic
	}
	return false, ""
}

// TextRange is a half-open range [Lo, Hi) of source_ip text that holds every
// address of one internal prefix (and possibly others: the caller classifies
// each address it finds there). The access log stores addresses as text, so
// an index range over a text prefix finds the internal ones without reading
// every row.
type TextRange struct{ Lo, Hi string }

// Ranges lists the text ranges that can hold an internal address: loopback
// (127.x and ::1), IPv4-mapped addresses, and one per subnet.
func (s Snapshot) Ranges() []TextRange {
	out := []TextRange{prefixRange("127."), prefixRange("::1"), prefixRange("::ffff:")}
	for _, p := range s.Subnets {
		out = append(out, subnetRanges(p)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Lo < out[j].Lo })
	// Drop a range inside the one before it.
	merged := out[:0]
	for _, r := range out {
		if n := len(merged); n > 0 && strings.HasPrefix(r.Lo, merged[n-1].Lo) {
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

// prefixRange is the range of every string that starts with p.
func prefixRange(p string) TextRange {
	b := []byte(p)
	b[len(b)-1]++
	return TextRange{Lo: p, Hi: string(b)}
}

// subnetRanges: an IPv4 subnet by its whole leading octets ("172.18." for
// 172.18.0.0/16 and for 172.18.0.0/20 alike); an IPv6 one by its first
// group, as the log writes it ("fd00:").
func subnetRanges(p netip.Prefix) []TextRange {
	a := p.Masked().Addr()
	if a.Is4() {
		o := a.As4()
		k := min(p.Bits()/8, 3)
		if k == 0 {
			// Shorter than /8: one range per first octet the subnet covers.
			n := 1 << (8 - p.Bits())
			var out []TextRange
			for i := 0; i < n; i++ {
				out = append(out, prefixRange(strconv.Itoa(int(o[0])+i)+"."))
			}
			return out
		}
		parts := make([]string, k)
		for i := 0; i < k; i++ {
			parts[i] = strconv.Itoa(int(o[i]))
		}
		return []TextRange{prefixRange(strings.Join(parts, ".") + ".")}
	}
	b := a.As16()
	if p.Bits() < 16 || (b[0] == 0 && b[1] == 0) {
		return nil
	}
	return []TextRange{prefixRange(strconv.FormatUint(uint64(b[0])<<8|uint64(b[1]), 16) + ":")}
}

// Classifier holds the current snapshot and refreshes it: interfaces and the
// proxy's address change only when a network is attached or the proxy is
// recreated.
type Classifier struct {
	proxyHost string
	// Injected for tests; the system's by default.
	ifaceAddrs func() ([]net.Addr, error)
	lookup     func(ctx context.Context, host string) ([]netip.Addr, error)
	readRoute  func() ([]byte, error)

	mu   sync.RWMutex
	snap Snapshot
}

// NewClassifier returns a classifier for a backend whose proxy is proxyHost.
// It knows only loopback until Refresh runs.
func NewClassifier(proxyHost string) *Classifier {
	return &Classifier{
		proxyHost:  proxyHost,
		ifaceAddrs: net.InterfaceAddrs,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		readRoute: readProcRoute,
	}
}

// Fixed returns a classifier that always uses snap, for tests.
func Fixed(snap Snapshot) *Classifier {
	return &Classifier{snap: snap}
}

// Snapshot returns the current snapshot.
func (c *Classifier) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap
}

// Refresh re-reads the interfaces, the proxy's address and the routes. It
// reports whether the backend is on the proxy's network.
func (c *Classifier) Refresh(ctx context.Context) bool {
	if c.ifaceAddrs == nil {
		return len(c.Snapshot().Proxy) > 0
	}
	addrs, err := c.ifaceAddrs()
	if err != nil {
		log.Warn().Err(err).Msg("client sources: could not list network interfaces; only loopback counts as internal")
	}
	var proxy []netip.Addr
	if c.proxyHost != "" {
		if a, err := netip.ParseAddr(c.proxyHost); err == nil {
			proxy = []netip.Addr{a}
		} else {
			lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			proxy, _ = c.lookup(lctx, c.proxyHost)
			cancel()
		}
	}
	route, _ := c.readRoute()
	snap := NewSnapshot(addrs, proxy, route)

	c.mu.Lock()
	changed := !equal(c.snap, snap)
	c.snap = snap
	c.mu.Unlock()
	if changed {
		log.Info().
			Strs("subnets", strs(snap.Subnets)).
			Strs("backend", strs(snap.Self)).
			Strs("proxy", strs(snap.Proxy)).
			Strs("host_gateway", strs(snap.Gateways)).
			Msg("client sources: addresses in these subnets, and loopback, are internal and not counted as clients")
	}
	return len(snap.Proxy) > 0
}

// Run refreshes the snapshot until ctx ends: every 30 seconds while the proxy
// has not resolved onto a shared network (it can start after the backend),
// every 10 minutes after.
func (c *Classifier) Run(ctx context.Context) {
	for {
		wait := 10 * time.Minute
		if !c.Refresh(ctx) {
			wait = 30 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func readProcRoute() ([]byte, error) {
	return os.ReadFile("/proc/net/route")
}

func equal(a, b Snapshot) bool {
	return slices.Equal(a.Subnets, b.Subnets) && slices.Equal(a.Self, b.Self) &&
		slices.Equal(a.Proxy, b.Proxy) && slices.Equal(a.Gateways, b.Gateways)
}

func strs[T interface{ String() string }](v []T) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = x.String()
	}
	return out
}
