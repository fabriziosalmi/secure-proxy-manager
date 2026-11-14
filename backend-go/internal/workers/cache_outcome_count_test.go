package workers

import (
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// The tailer's hook counts each parsed line under its cache outcome, from the
// status and blocked fields parseSquidLine fills in.
func TestCountProxyEntryCountsTheCacheOutcome(t *testing.T) {
	line := "1794643683.123    12 192.168.1.20 TCP_MEM_HIT/200 5120 GET http://a.test/x - HIER_NONE/- text/plain"
	entry := parseSquidLine(line)
	if entry == nil {
		t.Fatal("the line did not parse")
	}
	before := metrics.ProxyCacheCount(CacheHit)
	countProxyEntry(entry)
	if got := metrics.ProxyCacheCount(CacheHit) - before; got != 1 {
		t.Errorf("hit counter moved by %v, want 1", got)
	}
	tunnel := "1794643684.123  4000 192.168.1.20 TCP_TUNNEL/200 90000 CONNECT a.test:443 - HIER_DIRECT/1.2.3.4 -"
	before = metrics.ProxyCacheCount(CacheTunnel)
	countProxyEntry(parseSquidLine(tunnel))
	if got := metrics.ProxyCacheCount(CacheTunnel) - before; got != 1 {
		t.Errorf("tunnel counter moved by %v, want 1", got)
	}
}
