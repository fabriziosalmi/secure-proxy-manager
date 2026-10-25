package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Alert channels (a webhook, Gotify, ntfy, Teams) are URLs the operator types,
// and the backend POSTs to them. They are often self-hosted on the LAN, so a
// private address is a legitimate destination and SSRFSafeClient, which refuses
// every private range, would break them. What a notification must never reach
// is this host and this stack: loopback, link-local (the cloud metadata address
// 169.254.169.254 among it), unspecified and multicast addresses, and the
// networks the backend itself is attached to, where the WAF's and the proxy's
// management ports listen. Delivery used a plain http.Client, so a webhook URL
// such as http://waf:8080/ or http://127.0.0.1:5000/ was posted to from inside
// the stack, and a redirect from any endpoint was followed there too.

// BlockedTargetError is returned when a notification would reach an address
// internal to this host or stack.
type BlockedTargetError struct {
	Host string
	IP   net.IP
}

func (e *BlockedTargetError) Error() string {
	return fmt.Sprintf("refused: %s resolves to %s, an address of this host or of the proxy stack", e.Host, e.IP)
}

// IsInternalTarget reports whether ip is an address a notification must not
// reach: loopback, link-local, unspecified, multicast, or inside one of own,
// the networks this process is attached to.
func IsInternalTarget(ip net.IP, own []netip.Prefix) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	if a.Is4() && a.As4()[0] == 0 { // 0.0.0.0/8
		return true
	}
	for _, p := range own {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// OwnNetworks are the networks of this process's interfaces, loopback and
// link-local excluded (IsInternalTarget refuses those anyway). In the shipped
// compose they are the frontend and proxy-internal networks. With host
// networking they would include the LAN itself; such a deployment must reach
// its alert services by a routed address.
func OwnNetworks() []netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		out = append(out, netip.PrefixFrom(addr, ones).Masked())
	}
	return out
}

// CheckNotifyURL is the shape check applied when a notification URL is saved:
// http or https, a host, no credentials in it, and no literal address or name
// that can only mean this host. Names that resolve inside the stack are
// refused at delivery time by NotifyClient, which sees the resolved address.
func CheckNotifyURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("must be an http or https URL, such as https://alerts.example.com/hook")
	}
	if u.User != nil {
		return fmt.Errorf("must not carry a user name or password: use the token setting instead")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("must not point at this host: use an address the backend can reach on your network")
	}
	if ip := net.ParseIP(host); ip != nil && IsInternalTarget(ip, nil) {
		return fmt.Errorf("must not point at a loopback, link-local or multicast address: use an address the backend can reach on your network")
	}
	return nil
}

// NotifyClient is the HTTP client notifications are delivered with. It checks
// the resolved address at dial time (so a name cannot be re-pointed between a
// check and the connection), refuses internal targets, and does not follow
// redirects: a redirect is reported as the answer it is.
func NotifyClient(timeout time.Duration) *http.Client {
	own := OwnNetworks()
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
				if len(ips) == 0 {
					return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
				}
				for _, ipa := range ips {
					if IsInternalTarget(ipa.IP, own) {
						return nil, &BlockedTargetError{Host: host, IP: ipa.IP}
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
			},
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		},
	}
}
