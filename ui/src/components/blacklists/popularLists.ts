/**
 * The public lists offered under "Popular lists". The backend fetches each
 * one; the import records the URL as the entries' source and the name as its
 * label, so the list can be removed as a whole later. CI reads the url: lines
 * of this file and checks that each answers 200 (ci.yml, list URLs).
 */
export interface PopularList {
  name: string;
  url: string;
  desc: string;
}

export const popularIpLists: readonly PopularList[] = [
  { name: 'Firehol Level 1', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', desc: 'General purpose blocklist against active threats' },
  { name: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/drop.txt', desc: 'Don\'t Route Or Peer: direct malware and botnet infrastructure' },
  { name: 'Spamhaus EDROP', url: 'https://www.spamhaus.org/drop/edrop.txt', desc: 'Extended DROP: sub-allocated netblocks of hijacked space' },
  { name: 'Emerging Threats', url: 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', desc: 'Known compromised hosts and botnet C&C servers' },
  { name: 'CINS Army', url: 'https://cinsarmy.com/list/ci-badguys.txt', desc: 'High-confidence malicious IP addresses' },
  { name: 'Stamparm Ipsum (L3+)', url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt', desc: 'Daily threat intelligence feed: IPs seen on 3 or more blacklists' },
  { name: 'Blocklist.de All', url: 'https://lists.blocklist.de/lists/all.txt', desc: 'All attack IPs reported to blocklist.de in the last 48 hours' },
];

// Every list here must fit the DNS sinkhole: the domain blacklist is capped
// (SPM_DNS_BLOCKLIST_MAX_DOMAINS, default 1M) because dnsmasq holds it in
// memory, about 200 MiB per million. The aggregated list (5.5M on 2026-10-24)
// got dnsmasq OOM-killed at the default limits and is not offered; NoTracking
// (archived 2023) and Talos (403 to non-browsers) are gone.
export const popularDomainLists: readonly PopularList[] = [
  { name: 'StevenBlack Unified', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', desc: 'Adware and malware hosts from several curated sources' },
  { name: 'URLhaus Malware', url: 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt', desc: 'Active malware distribution domains from abuse.ch URLhaus (malware-filter mirror)' },
  { name: 'Phishing Army', url: 'https://phishing.army/download/phishing_army_blocklist_extended.txt', desc: 'Domains actively involved in phishing campaigns' },
  { name: 'OISD Big', url: 'https://big.oisd.nl/domainswild', desc: 'Comprehensive ad, tracking and malware domain list' },
  { name: 'HaGeZi Multi Pro', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt', desc: 'Multi-source pro blocklist (ads, tracking, malware, phishing); the listed names are blocked, not their subdomains' },
  { name: 'DanPollock Hosts', url: 'https://someonewhocares.org/hosts/zero/hosts', desc: 'Dan Pollock\'s hand-maintained hosts file (ads, trackers)' },
];
