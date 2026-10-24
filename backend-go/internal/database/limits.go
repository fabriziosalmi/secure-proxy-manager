package database

import (
	"os"
	"strconv"
)

// DefaultDomainBlacklistLimit is the default for DomainBlacklistLimit.
const DefaultDomainBlacklistLimit = 1_000_000

// DomainBlacklistLimit is the most domains the blacklist may hold.
//
// dnsmasq keeps every blocked name in memory, two records each (0.0.0.0 and
// ::). Measured under the shipped dns container limit (256 MiB, 0.5 CPU):
// 195 MiB for one million domains, unchanged across SIGHUP reloads; the
// aggregated public list (5.5 million) got dnsmasq OOM-killed while loading,
// and with DNS gone the proxy resolves nothing. One million leaves about 60
// MiB of headroom. Raise SPM_DNS_BLOCKLIST_MAX_DOMAINS together with the dns
// service's memory limit, roughly 200 MiB per additional million.
func DomainBlacklistLimit() int {
	if v, err := strconv.Atoi(os.Getenv("SPM_DNS_BLOCKLIST_MAX_DOMAINS")); err == nil && v > 0 {
		return v
	}
	return DefaultDomainBlacklistLimit
}
