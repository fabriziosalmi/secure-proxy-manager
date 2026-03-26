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

export interface ListResponse<T> {
  data: T[];
  total: number;
}

export interface LogsPageData {
  data?: LogEntry[];
  logs?: LogEntry[];
  total?: number;
}

export interface LogStats {
  total_count: number;
  blocked_count: number;
  ip_blocks_count: number;
}

export interface TimelineEntry {
  time: string;
  total: number;
  blocked: number;
}

export interface SecurityScore {
  score: number;
}

export interface SettingRow {
  setting_name: string;
  setting_value: string;
}
