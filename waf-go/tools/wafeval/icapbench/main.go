// Command icapbench times REQMOD transactions sent straight to the WAF's
// ICAP port, without Squid, to split the cost of ICAP itself from the cost
// of Squid's ICAP client.
//
// Each transaction opens a TCP connection, as go-icap answers every one with
// "Connection: close", sends a REQMOD that encapsulates a GET with
// "Allow: 204", and reads the reply to its end. Two hosts are timed: a LAN
// address, which the WAF answers 204 without inspecting (transport only),
// and a public name, which goes through the engine.
//
//	icapbench -addr waf:1344 -n 2000
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

func transaction(addr, host, path string) (time.Duration, time.Duration, string, error) {
	t0 := time.Now()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, 0, "", err
	}
	defer func() { _ = c.Close() }()
	dial := time.Since(t0)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	hdr := fmt.Sprintf("GET http://%s%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: icapbench\r\n\r\n", host, path, host)
	req := fmt.Sprintf("REQMOD icap://%s/waf ICAP/1.0\r\nHost: %s\r\nAllow: 204\r\nX-Client-IP: 192.0.2.10\r\nEncapsulated: req-hdr=0, null-body=%d\r\n\r\n%s",
		addr, addr, len(hdr), hdr)
	if _, err := io.WriteString(c, req); err != nil {
		return 0, 0, "", err
	}
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		return 0, 0, "", err
	}
	_, _ = io.Copy(io.Discard, br) // the server closes after its reply
	return time.Since(t0), dial, strings.TrimSpace(status), nil
}

func pct(ds []time.Duration, p float64) float64 {
	i := int(p*float64(len(ds)-1) + 0.5)
	return float64(ds[i].Microseconds())
}

func main() {
	addr := flag.String("addr", "waf:1344", "WAF ICAP address")
	n := flag.Int("n", 2000, "transactions per host")
	flag.Parse()
	for _, h := range []struct{ name, host string }{
		{"lan (no inspection)", "192.168.1.10"},
		{"public (engine)", "bench.example.com"},
	} {
		var total, dial []time.Duration
		codes := map[string]int{}
		for i := 0; i < *n; i++ {
			d, dl, st, err := transaction(*addr, h.host, fmt.Sprintf("/b?i=%d", i))
			if err != nil {
				fmt.Fprintln(os.Stderr, "icapbench:", err)
				os.Exit(1)
			}
			total, dial = append(total, d), append(dial, dl)
			codes[st]++
		}
		sort.Slice(total, func(i, j int) bool { return total[i] < total[j] })
		sort.Slice(dial, func(i, j int) bool { return dial[i] < dial[j] })
		fmt.Printf("%-20s n=%d total p50=%.0fus p90=%.0fus p99=%.0fus | connect p50=%.0fus | %v\n",
			h.name, *n, pct(total, .5), pct(total, .9), pct(total, .99), pct(dial, .5), codes)
	}
}
