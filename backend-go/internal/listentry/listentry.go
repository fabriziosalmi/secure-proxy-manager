// Package listentry reads one line of a blocklist feed into the entry it
// names. The import (handlers) and the refresh (workers) read feeds with it,
// so a line means the same entry on both paths: the refresh compares a feed
// with the entries an import of it added, and a line one path took and the
// other refused would be removed as if the feed had dropped it.
package listentry

import (
	"net"
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

// Parse reads one line. The entry is the first field of the line, or, in
// the hosts-file form ("0.0.0.0 evil.example"), the name after the address,
// or, in adblock syntax ("||evil.example^"), the name the rule blocks.
// # and ; start a comment line, and after a space they start a comment that
// runs to the end of the line: feeds annotate entries
// ("0.0.0.0 docs.pipenv.org # https://github.com/...", "198.51.100.0/24 ;
// SBL123"), and the last field, which this used to take, was then the
// comment, so a hosts feed blocked github.com. A # with no space before it
// (a URL's fragment) is part of the entry.
func Parse(line string, kind Kind) (string, Verdict) {
	line = strings.TrimSpace(stripComment(line))
	if line == "" {
		return "", Ignored
	}
	if v, done := adblockLine(line); done {
		return "", v
	}
	if strings.HasPrefix(line, "||") {
		if kind != Domain {
			return "", Invalid
		}
		name, ok := adblockName(line)
		if !ok {
			return "", Invalid
		}
		return parseDomain(name)
	}
	parts := strings.Fields(line)
	entry := parts[0]
	if kind == Domain && len(parts) > 1 && net.ParseIP(parts[0]) != nil {
		entry = parts[1]
	}
	if kind == IP {
		return parseIP(entry)
	}
	return parseDomain(entry)
}

// adblockLine settles the adblock-syntax lines that name no entry: a
// comment (! ...), the header ([Adblock Plus 2.0]), and an exception
// (@@||name^), which allows rather than blocks and is skipped and counted.
// done is false for any other line.
func adblockLine(line string) (v Verdict, done bool) {
	switch {
	case strings.HasPrefix(line, "!"), strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
		return Ignored, true
	case strings.HasPrefix(line, "@@"):
		return Invalid, true
	}
	return 0, false
}

// adblockName is the name of an adblock rule that blocks a whole name and
// its subdomains: ||name^, optionally with $important. A rule with a path,
// a wildcard or another modifier blocks less (or other) than the name, so
// taking the name would block more than the list means: ok is false.
func adblockName(line string) (string, bool) {
	rest := strings.TrimPrefix(line, "||")
	name, after, found := strings.Cut(rest, "^")
	if !found || (after != "" && after != "$important") {
		return "", false
	}
	if name == "" || strings.ContainsAny(name, "/*|$^:") {
		return "", false
	}
	return name, true
}

// stripComment cuts line at a # or ; that starts it or follows a space or a
// tab.
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		if (line[i] == '#' || line[i] == ';') && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
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
