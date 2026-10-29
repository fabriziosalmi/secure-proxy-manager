/**
 * The four lists the Blacklists page manages, and how each is named, reached
 * and enforced. The URL keeps the list in ?tab=, so a link opens it and the
 * back button returns to the one before.
 */
import { formatDate, formatHourMinute, formatWhen } from '../../lib/format';
import type { ListEntry, ListSource } from '../../types';
import { formatCount } from '../../lib/format';

export type ListKey = 'blocked-ips' | 'blocked-domains' | 'allowed-ips' | 'allowed-domains';

export interface ListDef {
  key: ListKey;
  /** Tab label. */
  label: string;
  /** API path segment: /api/{path}, /api/{path}/sources, /api/{path}/export. */
  path: 'ip-blacklist' | 'domain-blacklist' | 'ip-whitelist' | 'domain-whitelist';
  /** The field of an entry that holds its value. */
  field: 'ip' | 'domain';
  allowed: boolean;
  /** "blocked IPs and networks", for counts in sentences. */
  plural: string;
  singular: string;
  searchPlaceholder: string;
  /** The single-entry field's label and example. */
  entryLabel: string;
  entryPlaceholder: string;
  /** What removing entries does, said in the confirmations; what is "it" or "them". */
  consequence: (what: 'it' | 'them') => string;
}

export const LISTS: readonly ListDef[] = [
  {
    key: 'blocked-ips',
    label: 'Blocked IPs',
    path: 'ip-blacklist',
    field: 'ip',
    allowed: false,
    plural: 'blocked IPs and networks',
    singular: 'blocked IP or network',
    searchPlaceholder: 'Search IPs and networks',
    entryLabel: 'IP address or network',
    entryPlaceholder: 'e.g. 203.0.113.7 or 198.51.100.0/24',
    consequence: (what) => `Clients can reach ${what} again once the proxy reloads the list.`,
  },
  {
    key: 'blocked-domains',
    label: 'Blocked domains',
    path: 'domain-blacklist',
    field: 'domain',
    allowed: false,
    plural: 'blocked domains',
    singular: 'blocked domain',
    searchPlaceholder: 'Search domains',
    entryLabel: 'Domain',
    entryPlaceholder: 'e.g. ads.example.com',
    consequence: (what) => `Clients can reach ${what} again once the DNS sinkhole and the proxy reload the list.`,
  },
  {
    key: 'allowed-ips',
    label: 'IP exceptions',
    path: 'ip-whitelist',
    field: 'ip',
    allowed: true,
    plural: 'IP exceptions',
    singular: 'IP exception',
    searchPlaceholder: 'Search IPs and networks',
    entryLabel: 'IP address or network',
    entryPlaceholder: 'e.g. 192.168.1.50 or 192.168.1.0/24',
    consequence: (what) => `The proxy stops letting ${what} past its direct-IP rule once it reloads the list.`,
  },
  {
    key: 'allowed-domains',
    label: 'Domain exceptions',
    path: 'domain-whitelist',
    field: 'domain',
    allowed: true,
    plural: 'domain exceptions',
    singular: 'domain exception',
    searchPlaceholder: 'Search domains',
    entryLabel: 'Domain',
    entryPlaceholder: 'e.g. github.com',
    consequence: (what) => `A blocked entry with the same name as ${what === 'it' ? 'this one' : 'these'} is enforced again once the lists are rewritten.`,
  },
];

export const DEFAULT_LIST: ListKey = 'blocked-ips';

export function listByKey(key: string | null): ListDef {
  return LISTS.find((l) => l.key === key) ?? LISTS[0];
}

/**
 * "IP", "Network, 1,024 addresses", "IPv6 network", "Domain": what the entry
 * is, read from its value. The Entry column already shows the prefix, so the
 * kind says how much it covers; "Network /22" repeated it. An IPv6 network
 * larger than 2^20 addresses is named without a count no one reads.
 */
export function entryKind(list: ListDef, value: string): string {
  if (list.field === 'domain') return 'Domain';
  const slash = value.indexOf('/');
  if (slash < 0) return 'IP';
  const v6 = value.includes(':');
  const bits = (v6 ? 128 : 32) - Number(value.slice(slash + 1));
  if (!Number.isInteger(bits) || bits < 0) return v6 ? 'IPv6 network' : 'Network';
  if (bits === 0) return 'IP';
  if (bits > 20 && v6) return 'IPv6 network';
  return `${v6 ? 'IPv6 network' : 'Network'}, ${formatCount(2 ** bits)} addresses`;
}

/** The description the importer used to write, which only repeated the date. */
const LEGACY_IMPORT_DESC = /^Imported on \d{4}-\d{2}-\d{2}$/;

/** A description worth showing: typed by someone, not the old import stamp. */
export function shownDescription(entry: ListEntry): string | null {
  const d = entry.description?.trim();
  return d && !LEGACY_IMPORT_DESC.test(d) ? d : null;
}

export const UNRECORDED = 'Source not recorded';

/** The name a source is shown under, the same in both tables. */
export function sourceName(kind: string | null | undefined, source?: string | null, label?: string | null): string {
  switch (kind) {
    case 'url':
      return label || hostOf(source ?? '') || 'URL import';
    case 'manual':
      return 'Manual';
    case 'paste':
      return 'Pasted list';
    case 'restore':
      return 'Restore';
    case 'geo':
      return `GeoIP: ${source ?? ''}`.trim();
    case 'preset':
      // The backend's name for it: "Common services: Docker".
      return label || `Common services: ${source ?? ''}`.trim();
    default:
      return UNRECORDED;
  }
}

/** The line under a source's name: the URL it was fetched from, or why it has none. */
export function sourceDetail(s: Pick<ListSource, 'kind' | 'source' | 'label' | 'first_added'>): string | null {
  if (s.kind === 'url') return s.source || null;
  if (s.kind === 'unrecorded') return 'Added before sources were recorded';
  // Each paste and each restore is a source of its own: the time tells two
  // apart.
  // To the second: two pastes a minute apart must read differently.
  if (s.kind === 'paste') return s.first_added ? `Pasted ${formatWhen(s.first_added, { style: 'full' })}` : null;
  if (s.kind === 'restore') return s.first_added ? `Restored ${formatWhen(s.first_added, { style: 'full' })}` : null;
  return null;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** "08:00" today, "Yesterday 08:00", "Sun 25 08:00" in the last week, "2026-10-21 08:00" before (formatWhen, glance). */
export function shortDateTime(ts: string): string {
  return ts ? formatWhen(ts, { style: 'glance' }) : 'Not recorded';
}

/** "Sun 25 08:00 to 08:02" (the first time as shortDateTime writes it), or one time when the range is one minute. */
export function addedRange(first: string, last: string): string {
  if (!first) return 'Not recorded';
  const a = shortDateTime(first);
  const b = shortDateTime(last || first);
  if (a === b) return a;
  return formatDate(first) === formatDate(last) ? `${a} to ${formatHourMinute(last)}` : `${a} to ${b}`;
}

export type AddMethod = 'single' | 'paste' | 'url' | 'popular' | 'geo';

/** The ways to add to a list: the import endpoint feeds the blocked lists only. */
export function methodsFor(list: ListDef): AddMethod[] {
  if (list.allowed) return ['single', 'paste'];
  return list.field === 'ip' ? ['single', 'paste', 'url', 'popular', 'geo'] : ['single', 'paste', 'url', 'popular'];
}

/** The name a source goes by in its row and in the removal confirmation. */
export function sourceTitle(s: Pick<ListSource, 'kind' | 'source' | 'label'>): string {
  return sourceName(s.kind, s.source, s.label);
}
