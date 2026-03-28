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

export interface DomainWhitelistEntry {
  id: number;
  domain: string;
  type: 'fqdn' | 'url-regex';
  description: string | null;
  added_date: string;
}

export interface WhitelistEntry {
  id: number;
  ip: string;
  description: string | null;
  added_date: string;
}

export interface LogEntry {
  id?: number;
  timestamp: string;
  client_ip: string;
  method: string;
  destination: string;
  status: string;
  bytes: number | null;
}

export interface LogsPageData {
  data?: LogEntry[];
  logs?: LogEntry[];
  total?: number;
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
}

// Dashboard / Analytics types
export interface DashboardSummary {
  total_requests: number;
  blocked_requests: number;
  today_requests: number;
  today_blocked: number;
  top_blocked: { dest: string; count: number }[];
  top_clients: { ip: string; count: number }[];
  threat_categories: { category: string; count: number }[];
  recent_blocks: { timestamp: string; source_ip: string; method: string; destination: string; status: string }[];
  ip_blacklist_count: number;
  domain_blacklist_count: number;
  waf?: WafStats;
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

export interface CacheStats {
  hit_rate: number;
  hit_ratio?: number;
  byte_hit_rate: number;
  cache_size: string;
  objects_cached: number;
  bandwidth_saved?: string;
  bytes_saved?: number;
  hits?: number;
  misses?: number;
  requests?: number;
}
