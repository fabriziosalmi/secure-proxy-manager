// Package listentry reads one line of a blocklist feed into the entry it
// names. The import (handlers) and the refresh (workers) read feeds with it,
// so a line means the same entry on both paths: the refresh compares a feed
// with the entries an import of it added, and a line one path took and the
// other refused would be removed as if the feed had dropped it.
package listentry

import (
	"net/url"
	"strings"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/netguard"
)

// Verdict is what a line comes to.
type Verdict int

const (
	Ignored  Verdict = iota // blank line or comment, not counted at all
	Accepted                // an entry
	Invalid                 // counted as skipped
	Bogon                   // a private or reserved range: skipped, and counted apart
)

// Kind is the list a feed is read for.
type Kind string

const (
	IP     Kind = "ip"
	Domain Kind = "domain"
)

// Parse reads one line. The entry is the last field, which takes both a bare
// list and the hosts-file form ("0.0.0.0 evil.example"); # and ; start a
// comment line.
func Parse(line string, kind Kind) (string, Verdict) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return "", Ignored
	}
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", Ignored
	}
	entry := parts[len(parts)-1]
	if kind == IP {
		return parseIP(entry)
	}
	return parseDomain(entry)
}

func parseIP(entry string) (string, Verdict) {
	if !netguard.IsValidCIDR(entry) {
		return "", Invalid
	}
	// Firehol and bogon feeds include RFC 1918 and loopback ranges; the IP
	// blacklist is a destination ACL denied before LAN destinations are
	// allowed, so one of them would cut every client off from the LAN.
	if netguard.IsLANBogonCIDR(entry) {
		return "", Bogon
	}
	return entry, Accepted
}

func parseDomain(entry string) (string, Verdict) {
	// A URL names its host.
	if strings.HasPrefix(entry, "http://") || strings.HasPrefix(entry, "https://") {
		u, err := url.Parse(entry)
		if err != nil || u.Hostname() == "" {
			return "", Invalid
		}
		entry = u.Hostname()
	}
	if !strings.Contains(entry, ".") || strings.HasPrefix(entry, ".") || strings.HasSuffix(entry, ".") ||
		!netguard.IsValidDomainEntry(entry) {
		return "", Invalid
	}
	return entry, Accepted
}
