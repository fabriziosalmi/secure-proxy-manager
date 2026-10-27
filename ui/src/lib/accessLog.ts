/**
 * The access log page's filters and the facts it shows about one row, kept
 * apart from the page so each rule is tested on its own.
 *
 * The filters live in the URL (?q=&outcome=&client=&rule=), so a link opens
 * the same view: the Clients page links here with ?client=. Whether internal
 * traffic is shown is the viewer's own choice and lives in localStorage.
 */
import type { LogEntry } from '../types';

export type Outcome = 'all' | 'allowed' | 'blocked';

export interface LogFilters {
  /** A substring of the destination (host or URL). */
  q: string;
  outcome: Outcome;
  /** One source address, exact; empty for every client. */
  client: string;
  /** A block_reason key; empty for any rule. */
  rule: string;
}

export const NO_FILTERS: LogFilters = { q: '', outcome: 'all', client: '', rule: '' };

export function readFilters(params: URLSearchParams): LogFilters {
  const outcome = params.get('outcome');
  return {
    q: params.get('q')?.trim() ?? '',
    outcome: outcome === 'allowed' || outcome === 'blocked' ? outcome : 'all',
    client: params.get('client')?.trim() ?? '',
    rule: params.get('rule')?.trim() ?? '',
  };
}

/** The URL query for f; a filter left at its default is left out. */
export function writeFilters(f: LogFilters): URLSearchParams {
  const p = new URLSearchParams();
  if (f.q) p.set('q', f.q);
  if (f.outcome !== 'all') p.set('outcome', f.outcome);
  if (f.client) p.set('client', f.client);
  if (f.rule) p.set('rule', f.rule);
  return p;
}

export const hasFilters = (f: LogFilters) => f.q !== '' || f.outcome !== 'all' || f.client !== '' || f.rule !== '';

/** The GET /api/logs (and /api/logs/export) parameters for f. */
export function apiParams(f: LogFilters, showInternal: boolean): URLSearchParams {
  const p = new URLSearchParams();
  if (f.q) p.set('q', f.q);
  if (f.outcome !== 'all') p.set('outcome', f.outcome);
  if (f.client) p.set('source_ip', f.client);
  if (f.rule) p.set('reason', f.rule);
  if (showInternal) p.set('include_internal', 'true');
  return p;
}

/** The live feed sends blocked as 0 or 1, GET /api/logs as a boolean. */
export const isBlocked = (r: LogEntry) => r.blocked === true || r.blocked === 1;

/**
 * Parses an IPv4 address (or a masked IPv4 address like "192.168.1.x") into its
 * four octets, or null when it is not IPv4.
 */
function parseIpv4Octets(raw: string): number[] | null {
  const s = raw.trim().replace(/\.x$/i, '.0');
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    out.push(n);
  }
  return out;
}

/**
 * Parses an IPv6 address (or a masked IPv6 address like "2001:db8:1:2::x") into
 * eight 16-bit hextets, or null when it is not IPv6.
 */
function parseIpv6Hextets(raw: string): number[] | null {
  let s = raw.trim().split('%')[0];
  if (s.endsWith('::x') || s.endsWith('::X')) {
    s = s.slice(0, -1);
  } else if (s.endsWith(':x') || s.endsWith(':X')) {
    s = `${s.slice(0, -1)}0`;
  }
  if (!s.includes(':')) return null;
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parsePart = (part: string): number[] | null => {
    if (!part) return [];
    const tokens = part.split(':');
    const nums: number[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (i === tokens.length - 1 && t.includes('.')) {
        const v4 = parseIpv4Octets(t);
        if (!v4) return null;
        nums.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(t)) return null;
      nums.push(parseInt(t, 16));
    }
    return nums;
  };
  const left = parsePart(halves[0]);
  if (!left) return null;
  if (halves.length === 1) {
    return left.length === 8 ? left : null;
  }
  const right = parsePart(halves[1]);
  if (!right || left.length + right.length > 8) return null;
  const zeros = Array.from({ length: 8 - left.length - right.length }, () => 0);
  return [...left, ...zeros, ...right];
}

function matchesClientFilter(sourceIp: string | undefined, clientFilter: string): boolean {
  const ip = (sourceIp ?? '').trim();
  const filter = clientFilter.trim();
  if (!filter) return true;
  if (!filter.includes('/')) return ip === filter;

  const [netAddr, bitsStr] = filter.split('/');
  const bits = Number(bitsStr);
  if (!Number.isInteger(bits) || bits < 0) return false;

  const netV4 = parseIpv4Octets(netAddr);
  if (netV4) {
    if (bits > 32) return false;
    const rowV4 = parseIpv4Octets(ip);
    if (!rowV4) return false;
    const toU32 = (o: number[]) => ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (toU32(rowV4) & mask) === (toU32(netV4) & mask);
  }

  const netV6 = parseIpv6Hextets(netAddr);
  if (netV6) {
    if (bits > 128) return false;
    const rowV6 = parseIpv6Hextets(ip);
    if (!rowV6) return false;
    let rem = bits;
    for (let i = 0; i < 8 && rem > 0; i++) {
      const take = Math.min(16, rem);
      const mask = take === 16 ? 0xffff : (0xffff << (16 - take)) & 0xffff;
      if ((rowV6[i] & mask) !== (netV6[i] & mask)) return false;
      rem -= take;
    }
    return true;
  }
  return false;
}

/**
 * Converts a GDPR-masked address ("192.168.1.x" or "2001:db8:1:2::x") to the
 * /24 or /64 network CIDR that GET /api/logs accepts as source_ip, or null when
 * the address is not masked.
 */
export function maskedToNetwork(raw: string | undefined): string | null {
  const s = (raw ?? '').trim();
  if (!s) return null;
  if (/\.x$/i.test(s)) {
    const o = parseIpv4Octets(s);
    if (!o) return null;
    return `${o[0]}.${o[1]}.${o[2]}.0/24`;
  }
  if (/::x$/i.test(s)) {
    if (!parseIpv6Hextets(s)) return null;
    return `${s.slice(0, -1)}/64`;
  }
  if (/:x$/i.test(s)) {
    if (!parseIpv6Hextets(s)) return null;
    return `${s.slice(0, -1)}0/64`;
  }
  return null;
}

/**
 * Whether a row from the live feed belongs in the view f selects, by the
 * rules GET /api/logs applies: a client by exact address or network CIDR, the
 * outcome by the blocked flag, a rule among blocked rows, the destination by
 * substring (SQLite's LIKE ignores ASCII case), and the stack's own traffic
 * only when shown or when the client filter names it.
 */
export function matchesFilters(r: LogEntry, f: LogFilters, showInternal: boolean): boolean {
  if (f.client && !matchesClientFilter(r.source_ip, f.client)) return false;
  if (f.outcome === 'blocked' && !isBlocked(r)) return false;
  if (f.outcome === 'allowed' && isBlocked(r)) return false;
  if (f.rule && !(isBlocked(r) && r.reason === f.rule)) return false;
  if (f.q && !(r.destination ?? '').toLowerCase().includes(f.q.toLowerCase())) return false;
  if (!showInternal && !f.client && r.internal === true) return false;
  return true;
}

/** "TCP_TUNNEL/200" -> { squid: "TCP_TUNNEL", code: "200" }. */
export function splitStatus(status: string | undefined): { squid: string; code: string } {
  const s = status ?? '';
  const i = s.lastIndexOf('/');
  if (i < 0) return { squid: s, code: '' };
  return { squid: s.slice(0, i), code: s.slice(i + 1) };
}

/**
 * The tone of a row's HTTP code. A block is danger. A request the proxy let
 * through can still fail: a 503 to a name that does not resolve, a 404 from
 * the origin, a 000 when the client went away. Those are warning, so a
 * failure the proxy did not cause never reads as a success.
 */
export function statusTone(code: string, blocked: boolean): 'danger' | 'warning' | 'success' {
  if (blocked) return 'danger';
  const n = Number(code);
  if (!Number.isInteger(n) || n === 0 || n >= 400) return 'warning';
  return 'success';
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * The host a destination names, lower case: "ads.example.com:443" (CONNECT),
 * "http://ads.example.com/x", or a bare name (a DNS sinkhole row). Null for an
 * address literal or anything that is not a host name.
 */
export function requestHost(destination: string | undefined): string | null {
  const d = (destination ?? '').trim();
  if (!d || d.startsWith('[')) return null;
  let host: string;
  if (d.includes('://')) {
    try {
      host = new URL(d).hostname;
    } catch {
      return null;
    }
  } else {
    host = d.split('/')[0];
    if ((host.match(/:/g) ?? []).length > 1) return null; // an IPv6 literal
    host = host.split(':')[0];
  }
  host = host.toLowerCase().replace(/\.$/, '');
  if (!host || IPV4.test(host) || host.startsWith('[') || !host.includes('.')) return null;
  if (!/^[a-z0-9.-]+$/.test(host)) return null;
  return host;
}

/**
 * The rules a domain whitelist entry overrides: it takes the name off the
 * domain blacklist that Squid and the DNS sinkhole enforce. Nothing else.
 */
const DOMAIN_RULES = new Set(['domain_blacklist', 'domain_blacklist_dns', 'domain_blacklist_dns_reconstructed']);

/** The host "Allow this domain" would whitelist for r, or null when the rule that blocked r is not a domain rule. */
export function allowableDomain(r: LogEntry): string | null {
  if (!isBlocked(r) || !r.reason || !DOMAIN_RULES.has(r.reason)) return null;
  return requestHost(r.destination);
}

// Why, per rule, in the words of the rule itself (proxy/generate_squid_conf.sh
// and docs/design/block-reasons.md).
const WHY: Record<string, string> = {
  domain_blacklist: 'The name is on the domain blacklist; the proxy refused the request and served the block page.',
  domain_blacklist_dns:
    'The name is on the domain blacklist; the DNS sinkhole answered it with 0.0.0.0 and the proxy refused the request.',
  domain_blacklist_dns_reconstructed:
    'Logged before the proxy recorded why it blocked a request; reconstructed from the 503 Squid logged for a name ' +
    'already on the domain blacklist, when it tried the address the DNS sinkhole answered.',
  ip_blacklist: 'The destination address is on the IP blacklist.',
  direct_ip: 'The request named an IP address instead of a host name, and direct IP access is blocked.',
  egress_policy: 'Default-deny egress is on and the destination is not on the egress allowlist.',
  waf: 'The WAF matched one of its rules in the request or the response and blocked it.',
  proxy_auth: 'The proxy requires a username and password, and the request had none or a wrong one.',
  proxy_auth_unset: 'Proxy login is on but no proxy credentials are set, so the proxy refuses every client until they are set.',
  time_restriction: 'Access is limited to set hours, and the request came outside them.',
  content_filter: 'The URL ends in a file type the content filter blocks.',
  source_gate: 'The client address is not in a network allowed to use the proxy.',
  port_policy: 'The port is not one the proxy allows for this kind of request.',
  protocol_policy: 'The method or protocol is not allowed (FTP, or a method such as PUT or DELETE).',
  lists_unverified:
    'A blocklist did not match the manifest the backend wrote with it, so the proxy refused every request ' +
    'until a verified copy was loaded.',
  other: 'A proxy rule blocked it that the proxy did not name.',
  unclassified: 'Logged before the proxy recorded why it blocked a request, so the rule is not known.',
};

/** One sentence on why r was or was not blocked. */
export function whyText(r: LogEntry): string {
  if (!isBlocked(r)) return 'Allowed: no rule blocked it.';
  const reason = r.reason ?? '';
  if (WHY[reason]) return WHY[reason];
  if (!reason) return 'Blocked; this backend did not report which rule blocked it.';
  return `Blocked by the rule "${r.reason_label || reason}".`;
}
