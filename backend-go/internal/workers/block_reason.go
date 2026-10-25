package workers

import (
	"strings"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// Block reasons: the values of proxy_logs.block_reason. Each names the rule
// that decided the request, as recorded by Squid itself (the spm_reason note
// set by the spm_r_* ACLs in proxy/generate_squid_conf.sh) or by the WAF (the
// X-SPM-Reason ICAP header). See docs/design/block-reasons.md.
const (
	// ReasonNone: the request was not blocked.
	ReasonNone = "none"
	// ReasonUnclassified: the row carries no recorded reason. Rows written
	// before the column existed get it from the column default, and so does a
	// line from a Squid running a logformat without the reason fields. Its
	// blocked flag is the old status heuristic, kept as it was.
	ReasonUnclassified = "unclassified"

	ReasonIPBlacklist        = "ip_blacklist"
	ReasonDomainBlacklist    = "domain_blacklist"
	ReasonDomainBlacklistDNS = "domain_blacklist_dns"
	// ReasonDomainBlacklistDNSReconstructed: a row logged before reasons were
	// recorded that the one-off start-up step in database/reconstruct.go
	// reassigned: a /503 to a name on the domain blacklist, logged after the
	// name was added, which is what Squid logged when it connected to the
	// sinkhole's 0.0.0.0. Nothing writes it at ingestion; it is kept apart
	// from domain_blacklist_dns so a reconstructed block never reads as a
	// recorded one.
	ReasonDomainBlacklistDNSReconstructed = database.ReasonDNSReconstructed

	ReasonDirectIP        = "direct_ip"
	ReasonEgressPolicy    = "egress_policy"
	ReasonWAF             = "waf"
	ReasonProxyAuth       = "proxy_auth"
	ReasonTimeRestriction = "time_restriction"
	ReasonContentFilter   = "content_filter"
	ReasonSourceGate      = "source_gate"
	ReasonPortPolicy      = "port_policy"
	ReasonProtocolPolicy  = "protocol_policy"
	// ReasonListsUnverified: the fail-closed lists gate. A blocklist the
	// backend's manifest did not vouch for at boot has no copy in Squid, so
	// every client request is denied until the watchdog copies a verified one.
	ReasonListsUnverified = "lists_unverified"
	ReasonOther           = "other"
)

// reasonLabels are the display names, in the order the vocabulary is listed.
// A reason that is not here is not one this backend writes.
var reasonLabels = map[string]string{
	ReasonIPBlacklist:                     "IP blacklist",
	ReasonDomainBlacklist:                 "Domain blacklist",
	ReasonDomainBlacklistDNS:              "Domain blacklist (DNS)",
	ReasonDomainBlacklistDNSReconstructed: "Domain blacklist (DNS), reconstructed",
	ReasonDirectIP:                        "Direct IP",
	ReasonEgressPolicy:                    "Egress policy",
	ReasonWAF:                             "WAF",
	ReasonProxyAuth:                       "Proxy authentication",
	ReasonTimeRestriction:                 "Time restriction",
	ReasonContentFilter:                   "Content filter",
	ReasonSourceGate:                      "Source not allowed",
	ReasonPortPolicy:                      "Port policy",
	ReasonProtocolPolicy:                  "Method or protocol policy",
	ReasonListsUnverified:                 "Lists not verified",
	ReasonOther:                           "Other",
	ReasonUnclassified:                    "Unclassified (no reason recorded)",
	ReasonNone:                            "Not blocked",
}

// ReasonLabel is the display name of a block reason. An unknown value is shown
// as itself rather than folded into another reason.
func ReasonLabel(reason string) string {
	if l, ok := reasonLabels[reason]; ok {
		return l
	}
	return reason
}

// squidDenyReasons are the spm_reason values a Squid deny rule can set.
var squidDenyReasons = map[string]bool{
	ReasonIPBlacklist: true, ReasonDomainBlacklist: true, ReasonDomainBlacklistDNS: true,
	ReasonDirectIP: true, ReasonEgressPolicy: true, ReasonProxyAuth: true,
	ReasonTimeRestriction: true, ReasonContentFilter: true, ReasonSourceGate: true,
	ReasonPortPolicy: true, ReasonProtocolPolicy: true, ReasonListsUnverified: true,
	ReasonOther: true,
}

// squidReasonFields is the field count of a line in the spm logformat that
// carries the reason fields: the 10 stock fields, the WAF event id, the
// spm_reason note and the X-SPM-Reason ICAP header.
const squidReasonFields = 13

// classifySquid returns the block reason of one access-log line.
//
//   - note is the spm_reason the deciding http_access rule set. Every deny
//     rule sets its own; every allow rule sets "none". The proxy-auth rule sets
//     proxy_auth before its auth ACL is evaluated, so a request it lets through
//     carries it until an allow rule resets it: that is why "none" is a value
//     and not an absent note.
//   - icap is X-SPM-Reason from the last ICAP response. The WAF sets it to
//     "waf" on every block it answers, REQMOD and RESPMOD.
//   - hier is the hierarchy field (HIER_DIRECT/<address>). An address of
//     0.0.0.0 or :: is the DNS sinkhole's answer: Squid tried to connect to it,
//     which a config without the dns_sinkhole rule did (logged 503).
//   - action is Squid's result code. TCP_DENIED with no recognised note is a
//     Squid deny by a rule this backend does not know (other).
//
// A line without the reason fields is unclassified unless the sinkhole address
// identifies it: the old status heuristic cannot tell a Squid deny, a WAF block
// and an origin 403 apart, so it is not dressed up as a reason.
func classifySquid(nfields int, action, hier, note, icap string) string {
	if nfields >= squidReasonFields {
		if squidDenyReasons[note] {
			return note
		}
		if icap == ReasonWAF {
			return ReasonWAF
		}
	}
	if sinkholeAddr(hier) {
		return ReasonDomainBlacklistDNS
	}
	if nfields < squidReasonFields {
		return ReasonUnclassified
	}
	if note != "-" && note != ReasonNone {
		return ReasonOther // an annotation we did not write
	}
	if strings.HasPrefix(action, "TCP_DENIED") {
		return ReasonOther
	}
	return ReasonNone
}

// sinkholeAddr reports whether a hierarchy field names the address the DNS
// sinkhole answers (dnsmasq writes 0.0.0.0 and :: for every blacklisted name).
func sinkholeAddr(hier string) bool {
	i := strings.LastIndexByte(hier, '/')
	if i < 0 {
		return false
	}
	addr := hier[i+1:]
	return addr == "0.0.0.0" || addr == "::"
}
