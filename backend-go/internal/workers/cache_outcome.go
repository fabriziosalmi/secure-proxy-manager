package workers

import (
	"strings"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// What the proxy's cache did with one request, read from Squid's result code
// (the part of the access log's status before the slash, TCP_MEM_HIT in
// TCP_MEM_HIT/200). GET /api/analytics/cache-by-day and the
// spm_proxy_cache_*_total counters use the same classes.
const (
	// CacheHit: the response came from the cache without asking the server
	// (TCP_HIT, TCP_MEM_HIT, TCP_IMS_HIT, TCP_INM_HIT, TCP_NEGATIVE_HIT,
	// TCP_OFFLINE_HIT, TCP_CF_HIT, TCP_REFRESH_IGNORED).
	CacheHit = "hit"
	// CacheRevalidated: the cached copy was sent after the server was asked
	// whether it changed (TCP_REFRESH_UNMODIFIED), or could not be asked
	// (TCP_REFRESH_FAIL_OLD).
	CacheRevalidated = "revalidated"
	// CacheMiss: the response came from the server (TCP_MISS,
	// TCP_REFRESH_MODIFIED, TCP_CLIENT_REFRESH_MISS, TCP_SWAPFAIL_MISS,
	// TCP_REFRESH_FAIL_ERR, an _ABORTED variant of any of them).
	CacheMiss = "miss"
	// CacheTunnel: a CONNECT tunnel (TCP_TUNNEL). The proxy relays the bytes
	// without reading them, so they cannot be cached; with HTTPS inspection
	// the requests inside the tunnel are logged one by one.
	CacheTunnel = "tunnel"
	// CacheRefused: the proxy refused the request (blocked, or TCP_DENIED).
	CacheRefused = "refused"
	// CacheOther: anything else, such as NONE_NONE (the client went away or
	// sent something that is not a request) or TCP_REDIRECT.
	CacheOther = "other"
)

// CacheOutcomes are the classes in the order the API lists them.
var CacheOutcomes = []string{CacheHit, CacheRevalidated, CacheMiss, CacheTunnel, CacheRefused, CacheOther}

var cacheOutcomeLabels = map[string]string{
	CacheHit:         "From the cache",
	CacheRevalidated: "From the cache, checked with the server",
	CacheMiss:        "Fetched from the server",
	CacheTunnel:      "HTTPS tunnel (not cacheable)",
	CacheRefused:     "Refused by the proxy",
	CacheOther:       "Other",
}

// CacheOutcomeLabel is the API's label of a class.
func CacheOutcomeLabel(outcome string) string {
	if l, ok := cacheOutcomeLabels[outcome]; ok {
		return l
	}
	return outcome
}

// CacheOutcome classifies one access log row from its status ("TCP_HIT/200")
// and whether the proxy blocked it.
func CacheOutcome(status string, blocked bool) string {
	if blocked {
		return CacheRefused
	}
	action, _, _ := strings.Cut(strings.ToUpper(strings.TrimSpace(status)), "/")
	tags := map[string]bool{}
	for _, t := range strings.Split(action, "_") {
		tags[t] = true
	}
	switch {
	case tags["TUNNEL"]:
		return CacheTunnel
	case tags["DENIED"]:
		return CacheRefused
	case tags["REFRESH"]:
		switch {
		case tags["UNMODIFIED"], tags["FAIL"] && tags["OLD"]:
			return CacheRevalidated
		case tags["IGNORED"]:
			return CacheHit
		}
		return CacheMiss
	case tags["HIT"]:
		return CacheHit
	case tags["MISS"]:
		return CacheMiss
	}
	return CacheOther
}

func init() { metrics.InitProxyCache(CacheOutcomes) }

// countProxyEntry counts one parsed access log line: its outcome, and what
// the cache did with it.
func countProxyEntry(entry map[string]any) {
	blocked := entry["blocked"] == 1
	metrics.ProxyRequest(blocked)
	status, _ := entry["status"].(string)
	bytes, _ := entry["bytes"].(int64)
	metrics.ProxyCache(CacheOutcome(status, blocked), bytes)
}
