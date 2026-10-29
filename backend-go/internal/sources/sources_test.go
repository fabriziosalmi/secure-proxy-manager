package sources

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

// The shipped compose topology: the backend is on frontend (172.18.0.0/16,
// the network with the default route, gateway 172.18.0.1 on the host) and
// proxy-internal (172.19.0.0/16, internal: no gateway route). The proxy is on
// both and PROXY_HOST resolves to its frontend address.
const composeRoute = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
	"eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" +
	"eth1\t000013AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"

func ipnet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	n.IP = ip
	return n
}

func composeAddrs(t *testing.T) []net.Addr {
	return []net.Addr{
		ipnet(t, "127.0.0.1/8"),
		ipnet(t, "::1/128"),
		ipnet(t, "172.18.0.2/16"),
		ipnet(t, "fe80::42:acff:fe12:2/64"),
		ipnet(t, "172.19.0.3/16"),
	}
}

func composeSnapshot(t *testing.T) Snapshot {
	return NewSnapshot(composeAddrs(t), []netip.Addr{netip.MustParseAddr("172.18.0.4")}, []byte(composeRoute))
}

func TestClassifyInTheComposeTopology(t *testing.T) {
	s := composeSnapshot(t)
	cases := []struct {
		ip       string
		internal bool
		kind     string
	}{
		{"127.0.0.1", true, KindLoopback},
		{"::1", true, KindLoopback},
		{"172.18.0.2", true, KindBackend},
		{"172.18.0.4", true, KindProxy},
		{"172.18.0.1", true, KindHost},
		{"::ffff:172.18.0.1", true, KindHost},
		{"172.19.0.5", true, KindStack},
		{"172.18.200.7", true, KindStack},
		// A LAN in 172.16.0.0/12 that is not one of the container's subnets.
		{"172.20.5.9", false, KindPrivate},
		{"172.16.0.10", false, KindPrivate},
		{"192.168.1.109", false, KindPrivate},
		{"10.0.0.8", false, KindPrivate},
		{"8.8.8.8", false, KindPublic},
		// CGNAT and Tailscale's range: neither private nor public.
		{"100.100.1.1", false, ""},
		// Link-local: the backend's fe80:: interface is not a stack subnet.
		{"fe80::1", false, ""},
		{"not an ip", false, ""},
		{"", false, ""},
	}
	for _, c := range cases {
		internal, kind := s.Classify(c.ip)
		if internal != c.internal || kind != c.kind {
			t.Errorf("Classify(%q) = %v, %q; want %v, %q", c.ip, internal, kind, c.internal, c.kind)
		}
	}
}

func TestSnapshotReadsTheSharedSubnetsAndTheHostGateway(t *testing.T) {
	s := composeSnapshot(t)
	want := []string{"172.18.0.0/16", "172.19.0.0/16"}
	if len(s.Subnets) != len(want) {
		t.Fatalf("subnets %v, want %v", s.Subnets, want)
	}
	for i, w := range want {
		if s.Subnets[i].String() != w {
			t.Errorf("subnet %d = %s, want %s", i, s.Subnets[i], w)
		}
	}
	if len(s.Gateways) != 1 || s.Gateways[0].String() != "172.18.0.1" {
		t.Errorf("gateways %v, want [172.18.0.1]", s.Gateways)
	}
	if len(s.Self) != 2 {
		t.Errorf("self %v, want the two interface addresses", s.Self)
	}
}

// Run on a host, the backend's interfaces are the LAN's. They must not make
// every LAN device internal: the proxy is not on them (it is localhost).
// Only loopback and the host's own address are.
func TestBackendOnTheHostMakesOnlyLoopbackAndItselfInternal(t *testing.T) {
	addrs := []net.Addr{ipnet(t, "127.0.0.1/8"), ipnet(t, "192.168.1.10/24")}
	route := "Iface\tDestination\tGateway \tFlags\n" + "en0\t00000000\t0101A8C0\t0003\n"
	s := NewSnapshot(addrs, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, []byte(route))
	for _, ip := range []string{"192.168.1.50", "192.168.1.1"} {
		if internal, _ := s.Classify(ip); internal {
			t.Errorf("%s is internal with the backend on the host", ip)
		}
	}
	for _, ip := range []string{"127.0.0.1", "192.168.1.10"} {
		if internal, _ := s.Classify(ip); !internal {
			t.Errorf("%s is not internal", ip)
		}
	}
}

// Before the proxy resolves (it can start after the backend) no subnet is
// internal yet.
func TestUnresolvedProxyMakesOnlyLoopbackAndTheBackendInternal(t *testing.T) {
	s := NewSnapshot(composeAddrs(t), nil, []byte(composeRoute))
	for _, ip := range []string{"172.18.0.1", "172.18.0.4", "172.19.0.5"} {
		if internal, _ := s.Classify(ip); internal {
			t.Errorf("%s is internal before the proxy resolved", ip)
		}
	}
	if internal, kind := s.Classify("172.18.0.2"); !internal || kind != KindBackend {
		t.Errorf("the backend's own address: %v %q", internal, kind)
	}
	// Loopback, mapped, and the backend's two addresses.
	if len(s.Ranges()) != 5 {
		t.Errorf("ranges %v, want loopback, mapped and the backend's addresses", s.Ranges())
	}
}

func TestRangesCoverEveryInternalAddress(t *testing.T) {
	s := composeSnapshot(t)
	s.Subnets = append(s.Subnets, netip.MustParsePrefix("10.20.16.0/20"), netip.MustParsePrefix("fd00:abcd::/64"), netip.MustParsePrefix("44.0.0.0/6"))
	in := func(ip string) bool {
		for _, r := range s.Ranges() {
			if ip >= r.Lo && ip < r.Hi {
				return true
			}
		}
		return false
	}
	for _, ip := range []string{"127.0.0.1", "127.255.0.9", "::1", "::ffff:172.18.0.1", "172.18.0.1", "172.18.255.254",
		"172.19.0.3", "10.20.16.1", "10.20.31.200", "fd00:abcd::5", "44.1.2.3", "47.255.255.1"} {
		if !in(ip) {
			t.Errorf("%s is in no range: %v", ip, s.Ranges())
		}
	}
	for _, ip := range []string{"192.168.1.109", "172.20.0.1", "8.8.8.8", "48.0.0.1"} {
		if in(ip) {
			t.Errorf("%s is in a range: %v", ip, s.Ranges())
		}
	}
}

func TestClassifierRefreshUsesTheSystem(t *testing.T) {
	// PROXY_HOST does not resolve; PROXY_URL's host does.
	c := NewClassifier("unresolvable", "", "proxy")
	c.ifaceAddrs = func() ([]net.Addr, error) { return composeAddrs(t), nil }
	c.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "proxy" {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []netip.Addr{netip.MustParseAddr("172.18.0.4")}, nil
	}
	c.readRoute = func() ([]byte, error) { return []byte(composeRoute), nil }
	if internal, _ := c.Snapshot().Classify("172.18.0.1"); internal {
		t.Fatal("internal before the first refresh")
	}
	if !c.Refresh(context.Background()) {
		t.Fatal("Refresh did not find the proxy's network")
	}
	if internal, kind := c.Snapshot().Classify("172.18.0.1"); !internal || kind != KindHost {
		t.Errorf("after refresh: %v %q", internal, kind)
	}
}
