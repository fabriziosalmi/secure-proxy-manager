// Shared API response types

export interface IpEntry {
  id: number;
  ip: string;
  description: string | null;
  added_date: string;
}

export interface DomainEntry {
  id: number;
  domain: string;
  description: string | null;
  added_date: string;
}

export interface EgressEntry {
  id: number;
  entry: string;
  type: 'cidr' | 'domain';
  description: string | null;
  added_date: string;
}

export interface DomainWhitelistEntry {
  id: number;
  domain: string;
  /** Only 'fqdn' is reachable: url-regex entries were persisted but read by
   *  nothing, so they are now refused at the API (SECURE-DOM-07). */
  type: 'fqdn';
  description: string | null;
  added_date: string;
}

export interface WhitelistEntry {
  id: number;
  ip: string;
  description: string | null;
  added_date: string;
}

/** Where list entries came from (list_sources); 'unrecorded' names the entries added before sources were recorded. */
export type SourceKind = 'url' | 'manual' | 'geo' | 'paste' | 'restore' | 'unrecorded';

/** One row of GET /api/{list}: an entry of any of the four lists, with its source (null when not recorded). */
export interface ListEntry {
  id: number;
  ip?: string;
  domain?: string;
  description: string | null;
  added_date: string;
  source_id?: number | null;
  source_kind?: SourceKind | null;
  /** The URL of a URL source, the country code of a geo source. */
  source?: string | null;
  /** The Popular list name of a URL source. */
  source_label?: string | null;
}

/** One row of GET /api/{list}/sources: a source and the entries it added. */
export interface ListSource {
  /** Null for the entries whose source was not recorded. */
  id: number | null;
  kind: SourceKind;
  source: string;
  label: string;
  entries: number;
  first_added: string;
  last_added: string;
}

/** What the proxy recorded after merging an IP list for Squid. */
export interface IpAclStatus {
  entries: number;
  /** Networks Squid loads after overlapping and adjacent entries are merged. */
  networks: number;
  /** Lines that were not an address or CIDR. */
  dropped: number;
  written_at: number;
}

/** GET /api/blacklists/enforcement. A record the proxy has not written is null. */
export interface Enforcement {
  dns_blocklist_limit: number;
  domain_blacklist_entries: number;
  /** Blocked domains whose exact name is on the allowed list: left out of what DNS and Squid receive. */
  domain_blacklist_on_allowed: number;
  squid_domain_acl: SquidDomainAcl | null;
  squid_ip_blacklist: IpAclStatus | null;
  squid_ip_whitelist: IpAclStatus | null;
}

export interface LogEntry {
  id?: number;
  timestamp: string;
  source_ip: string;
  method: string;
  destination: string;
  status: string;
  bytes: number | null;
}

/** Pagination envelope shared by every collection endpoint (SECURE-API-02). */
export interface ListMeta {
  total: number;
  limit: number;
  offset: number;
}

/** A paginated collection. `data` always holds the collection; `meta` always
 *  holds the pagination. The previous `data? | logs?` union existed because the
 *  API returned three different shapes and the client could not tell which. */
export interface ListResponse<T> {
  data: T[];
  meta: ListMeta;
}

export type LogsPageData = ListResponse<LogEntry>;

export interface AuditEntry {
  id: number;
  username: string | null;
  action: string;
  target: string | null;
  details: string | null;
  timestamp: string;
}

export type AuditPageData = ListResponse<AuditEntry>;

export interface ClientStat {
  ip_address: string;
  requests: number;
  /** Client rows recorded as blocked, any reason, "unclassified" included. */
  blocked: number;
  last_seen: string;
  status: string;
  /** The stack's own traffic (loopback, the Docker host, the backend), not a device. Absent from older backends. */
  internal?: boolean;
  /** What the address is, where the backend can say ("Internal: this host", "Private network address"); may be empty. */
  kind?: string;
}

/** GET /api/clients/statistics: the clients with the most requests, then the internal sources. */
export interface ClientsData extends ListResponse<ClientStat> {
  /** total counts the clients other than internal sources; internal counts those. */
  meta: ListMeta & { internal?: number };
}

export interface ClientDomain {
  destination: string;
  requests: number;
  blocked: number;
}

export interface ClientRecent {
  timestamp: string;
  method: string;
  destination: string;
  status: string;
  bytes: number;
  /** The row's recorded blocked flag. Absent from older backends. */
  blocked?: boolean;
  reason?: string;
  reason_label?: string;
}

/** GET /api/clients/{ip}/details: every logged client request of the address, not only the last 7 days. */
export interface ClientDetail {
  ip_address: string;
  internal?: boolean;
  kind?: string;
  total_requests: number;
  blocked: number;
  first_seen: string;
  last_seen: string;
  top_domains: ClientDomain[];
  recent: ClientRecent[];
  /** The blocked requests by the rule that blocked them; "unclassified" for rows from before reasons were recorded. */
  blocked_by_reason?: ReasonCount[];
}

export interface TimelineEntry {
  time: string;
  total: number;
  blocked: number;
}

export interface SecurityScore {
  score: number;
  max_score: number;
  recommendations: string[];
}

export interface SettingRow {
  setting_name: string;
  setting_value: string;
  /** A write-only setting: the value is never returned. */
  secret?: boolean;
  /** A secret has a stored value, readable or not. */
  is_set?: boolean;
  /** A stored secret the backend cannot decrypt with its current key. */
  decrypt_failed?: boolean;
}

// Dashboard / Analytics types

/** Blocked client requests for one rule: reason is the stored key, label its display name. */
export interface ReasonCount {
  reason: string;
  label: string;
  count: number;
}

/** What the proxy recorded about Squid's own copy of the domain blacklist. */
export interface SquidDomainAcl {
  /** Names in the list after dropping "*." and duplicates, the count the limit applies to. */
  names: number;
  /** SPM_SQUID_DOMAIN_ACL_MAX on the proxy. */
  limit: number;
  /** Whether Squid holds the list; when false only the DNS sinkhole blocks it. */
  held: boolean;
  written_at: number;
}

export interface DashboardSummary {
  total_requests: number;
  blocked_requests: number;
  today_requests: number;
  today_blocked: number;
  /** The last 24 hours, client requests. Absent from older backends. */
  last_24h_requests?: number;
  last_24h_blocked?: number;
  /** Distinct client source IPs in the last 24 hours. */
  last_24h_clients?: number;
  /** Internal sources (the stack's own traffic) left out of every count, and their requests, in the last 24 hours. */
  last_24h_internal_sources?: number;
  last_24h_internal_requests?: number;
  /** Newest client request in the last 24 hours (UTC, no zone marker), null when none. */
  last_request_at?: string | null;
  /** Hosts with the most blocked requests in the last 24 hours, with the rules that blocked them. */
  top_blocked: { dest: string; count: number; reasons?: ReasonCount[] }[];
  top_clients: { ip: string; count: number }[];
  threat_categories: { category: string; count: number }[];
  blocked_by_reason?: ReasonCount[];
  blocked_by_reason_24h?: ReasonCount[];
  recent_blocks: {
    timestamp: string;
    source_ip: string;
    method: string;
    destination: string;
    /** The destination reduced to its host. */
    host?: string;
    status: string;
    reason?: string;
    reason_label?: string;
  }[];
  ip_blacklist_count: number;
  domain_blacklist_count: number;
  /** Null when the proxy has not written its record. */
  squid_domain_acl?: SquidDomainAcl | null;
  waf?: WafStats | null;
  // Why waf is null: the WAF refused the backend's credential, could not be
  // reached, or answered with an error. Absent from older backends.
  waf_status?: 'ok' | 'auth_failed' | 'unreachable' | 'error';
}

export interface WafStats {
  total_inspected: number;
  total_requests: number;
  total_blocked: number;
  avg_entropy: number;
  avg_url_entropy: number;
  high_entropy_count: number;
  requests_per_min: number;
  requests_last_minute: number;
  top_blocked_categories: { key: string; count: number }[];
}

export interface ShadowItService {
  name: string;
  domain: string;
  requests: number;
  category: string;
}

export interface FileExtData {
  extensions: { ext: string; count: number }[];
  categories: { category: string; count: number }[];
}

export interface ServiceTypeData {
  methods: { name: string; count: number }[];
  service_types: { name: string; count: number }[];
}

export interface TopDomain {
  domain: string;
  count: number;
}

/**
 * GET /api/cache/statistics: the proxy's last collection of Squid's cache
 * statistics (backend-go/internal/handlers/cache_stats.go). current: within
 * three collection intervals; stale: collected, but not since then;
 * not_collected: no record; unreadable: a record the backend cannot read.
 */
export type CacheStatsState = 'current' | 'stale' | 'not_collected' | 'unreadable';

/** Squid's numbers as it printed them; null where it printed none, never 0. Percentages are percent (64.7). */
export interface CacheStats {
  state: CacheStatsState;
  /** UTC, "2026-10-25 12:15:28". */
  collected_at: string | null;
  age_s: number | null;
  interval_s: number | null;
  stale_after_s: number | null;
  request_hit_ratio_5min_pct: number | null;
  request_hit_ratio_60min_pct: number | null;
  byte_hit_ratio_5min_pct: number | null;
  byte_hit_ratio_60min_pct: number | null;
  disk_used_kb: number | null;
  disk_capacity_kb: number | null;
  disk_used_pct: number | null;
  memory_used_kb: number | null;
  memory_used_pct: number | null;
  uptime_s: number | null;
  store_entries: number | null;
  memory_objects: number | null;
  disk_objects: number | null;
}
