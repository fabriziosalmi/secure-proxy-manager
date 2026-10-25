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

/** The backend's refusal of "*.example.com", in the same words. */
export const WILDCARD_REFUSAL =
  'Write .example.com, with a leading dot, to allow example.com and every name under it: *.example.com would match nothing.';

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

/** What one entry allows, in words. */
export function egressEntryKind(e: Pick<EgressEntry, 'entry' | 'type'>): string {
  if (e.type === 'cidr') return e.entry.includes('/') ? 'Network' : 'IP address';
  return e.entry.startsWith('.') ? 'Domain and its subdomains' : 'Exact domain';
}
