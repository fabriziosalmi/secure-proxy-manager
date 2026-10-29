/**
 * The egress allowlist's entries as the proxy reads them. The domains reach
 * Squid verbatim as a dstdomain ACL and the addresses as a dst ACL
 * (proxy/generate_squid_conf.sh): an exact name allows that host only, a
 * leading dot allows the domain and every name under it, "*." matches
 * nothing, and a network allows every address in it.
 */
import { isValidDomain, isValidIP } from './validation';
import type { EgressEntry } from '../types';

export type EgressKind = 'domain' | 'ip';

/** The refusal of "*.example.com", in the words of the form. */
export const WILDCARD_REFUSAL =
  'Write example.com and tick Include subdomains to allow example.com and every name under it: *.example.com would match nothing.';

// A dotted quad with an optional prefix length: 203.0.113.7, 203.0.113.0/24.
const DOTTED_QUAD = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/;

/** What is wrong with a destination before it is sent, or null. */
export function checkDestination(kind: EgressKind, raw: string): string | null {
  const value = raw.trim().toLowerCase();
  if (!value) return 'Enter a destination.';
  const looksLikeAddress = value.includes(':') || DOTTED_QUAD.test(value);
  const name = value.replace(/^\./, '');
  if (kind === 'domain') {
    if (looksLikeAddress) return 'This is an address: choose IP or network as the kind.';
    if (value.startsWith('*.')) return WILDCARD_REFUSAL;
    if (!isValidDomain(name)) return `"${value}" is not a domain name: labels of letters, digits and hyphens separated by dots.`;
    return null;
  }
  // An IPv6 address or network is checked by the backend, which accepts it.
  if (value.includes(':') || isValidIP(value)) return null;
  if (!looksLikeAddress && isValidDomain(name)) return 'This is a domain name: choose Domain as the kind.';
  return `"${value}" is not an IP address or network, such as 203.0.113.7 or 203.0.113.0/24.`;
}

/** An entry as the page shows it: the name, without the leading dot that stores "and its subdomains". */
export function shownEntry(e: Pick<EgressEntry, 'entry' | 'type'>): string {
  return e.type === 'domain' ? e.entry.replace(/^\./, '') : e.entry;
}

/** An entry in a sentence: "example.com and its subdomains", or the entry. */
export function describeEntry(e: Pick<EgressEntry, 'entry' | 'type'>): string {
  return e.type === 'domain' && e.entry.startsWith('.') ? `${shownEntry(e)} and its subdomains` : shownEntry(e);
}

/** What one entry allows, in words. */
export function egressEntryKind(e: Pick<EgressEntry, 'entry' | 'type'>): string {
  if (e.type === 'cidr') return e.entry.includes('/') ? 'Network' : 'IP address';
  return e.entry.startsWith('.') ? 'Domain and its subdomains' : 'Exact domain';
}

/**
 * What egress default-deny leaves reachable, from proxy/generate_squid_conf.sh:
 * the deny rule is inserted before "http_access allow localnet", after
 * "http_access allow ip_whitelist" (a dst ACL: the addresses on Allowed IPs
 * are destinations) and "http_access allow local_dst", where
 * "acl local_dst dst 10.0.0.0/8 192.168.0.0/16" (172.16.0.0/12 is left out
 * because Docker's own networks use it). The Egress page says the same.
 */
export const LAN_DESTINATIONS = ['10.0.0.0/8', '192.168.0.0/16'];

export const EGRESS_EMPTY_REACH =
  'With default deny on and an empty list, clients reach only LAN destinations and the addresses on IP exceptions.';

export const EGRESS_DENY_HELP =
  `Refuses every destination that is not on the default-deny allowlist, except LAN destinations (${LAN_DESTINATIONS.join(' and ')}) and the addresses on IP exceptions, which the proxy allows before this rule.`;
