/**
 * The Settings page's static map: its sections in task order, the keys each
 * section saves, and how each key takes effect. Nothing here is a value: every
 * value the page shows comes from GET /api/settings.
 */
import { SECRET_KEYS } from './secrets';

export type SectionId = 'overview' | 'access' | 'filtering' | 'inspection' | 'alerts' | 'logs' | 'admin' | 'engine' | 'appearance';

export interface SectionDef {
  id: SectionId;
  label: string;
  /** One line under the section title: what it is for. */
  purpose: string;
  /** Words GlobalSearch matches to this section. */
  keywords: string[];
}

export const SECTIONS: SectionDef[] = [
  { id: 'overview', label: 'Summary', purpose: 'What needs attention, and how to connect a device.', keywords: ['status', 'connect', 'device', 'profile', 'preset', 'attention', 'overview'] },
  { id: 'access', label: 'Clients and access', purpose: 'Who may use the proxy, when, and how fast.', keywords: ['auth', 'login', 'password', 'time', 'hours', 'bandwidth', 'throttle', 'clients'] },
  { id: 'filtering', label: 'Filtering', purpose: 'What clients are blocked from reaching. The lists themselves are under Blacklists and Default-deny allowlist.', keywords: ['egress', 'safesearch', 'youtube', 'download', 'extension', 'refresh', 'blocklist'] },
  { id: 'inspection', label: 'Inspection', purpose: 'WAF heuristics and HTTPS inspection.', keywords: ['waf', 'heuristic', 'https', 'ssl', 'bump', 'certificate', 'ca', 'regex', 'pattern', 'rule'] },
  { id: 'alerts', label: 'Alerts', purpose: 'Where block alerts go, and proof that they arrive.', keywords: ['notification', 'telegram', 'gotify', 'ntfy', 'teams', 'webhook', 'token', 'test'] },
  { id: 'logs', label: 'Logs and privacy', purpose: 'How long logs are kept and what the log view shows.', keywords: ['retention', 'gdpr', 'privacy', 'mask'] },
  { id: 'admin', label: 'Admin and backup', purpose: 'Password, backup and restore, maintenance.', keywords: ['password', 'backup', 'restore', 'cache', 'reload', 'maintenance'] },
  { id: 'engine', label: 'Proxy engine', purpose: 'Rarely touched: a mistake here can stop every client.', keywords: ['port', 'cache', 'memory', 'ssl ports', 'offline', 'hit ratio', 'bypass'] },
  // A preference of this browser, not a setting of the proxy: last.
  { id: 'appearance', label: 'Appearance', purpose: 'How this dashboard looks in this browser.', keywords: ['theme', 'dark', 'light', 'colour', 'color'] },
];

export const DEFAULT_SECTION: SectionId = 'overview';

export function sectionById(id: string | undefined): SectionDef | undefined {
  return SECTIONS.find((s) => s.id === id);
}

export function sectionPath(id: SectionId): string {
  return `/settings/${id}`;
}

/**
 * The keys each section saves. A section's Save sends all of its keys that
 * have a value (stored or typed), so a toggle always travels with its
 * parameters: the backend rewrites the time and bandwidth files only when
 * their toggle is in the request. Internal keys (wizard_completed,
 * default_password_changed) belong to no section and are never sent.
 */
export const SECTION_KEYS: Record<SectionId, string[]> = {
  overview: [],
  access: [
    'enable_proxy_auth', 'proxy_auth_username', 'proxy_auth_password',
    'enable_time_restrictions', 'time_restriction_start', 'time_restriction_end',
    'enable_bandwidth_limits', 'bandwidth_limit_mbps', 'bandwidth_limit_per_user_kbps',
  ],
  filtering: [
    'egress_default_deny', 'egress_provider_refresh_hours',
    'enable_content_filtering', 'blocked_file_types',
    'enable_safesearch', 'enable_youtube_restricted',
    'auto_refresh_enabled', 'auto_refresh_hours',
  ],
  inspection: [
    'ssl_bump_enabled',
    'waf_h_entropy', 'waf_h_beaconing', 'waf_h_pii', 'waf_h_sharding', 'waf_h_ghosting', 'waf_h_sequence',
  ],
  alerts: [
    'enable_notifications',
    'notify_waf_block', 'notify_login_failure', 'notify_min_level',
    'notify_group_window_minutes', 'notify_max_per_hour',
    'webhook_url', 'webhook_bearer_token',
    'telegram_bot_token', 'telegram_chat_id', 'gotify_url', 'gotify_token',
    'ntfy_url', 'ntfy_topic', 'teams_webhook_url',
  ],
  logs: ['gdpr_mode', 'log_retention_days'],
  admin: [],
  // proxy_port is shown, not saved: docker-compose.yml publishes 3128 and
  // its health check looks for 3128, so it changes with compose and .env.
  engine: [
    'cache_size', 'memory_cache', 'extra_ssl_ports',
    'aggressive_caching_enabled', 'cache_bypass_domains', 'enable_offline_mode',
  ],
  // Stored in the browser (ThemeProvider), never sent to the backend.
  appearance: [],
};

/** The section a key belongs to, for a backend error that names it. */
export function sectionOfKey(key: string): SectionId | undefined {
  return SECTIONS.find((s) => SECTION_KEYS[s.id].includes(key))?.id;
}

export function isSecretKey(key: string): boolean {
  return SECRET_KEYS.has(key);
}

/**
 * How a saved key takes effect, from the code that reads it:
 * reload: the backend rewrites a /config file and the proxy must regenerate
 *   squid.conf (POST /api/maintenance/reload-config).
 * dns: a marker file the dns container watches every 2 seconds; it restarts
 *   dnsmasq when it changes (dns/entrypoint.sh).
 * waf: pushed to the running WAF on save and by a reconciler.
 * live: read from the database on every use.
 * daily: read by the daily log retention pass.
 * cycle: read by the blocklist refresh worker when its current wait ends.
 */
export type ApplyMode = 'reload' | 'dns' | 'waf' | 'live' | 'daily' | 'cycle' | 'provider_cycle';

export const APPLY_LABEL: Record<ApplyMode, string> = {
  reload: 'Proxy reload',
  dns: 'DNS',
  waf: 'WAF',
  live: 'Live',
  daily: 'Daily',
  cycle: 'Next cycle',
  provider_cycle: 'Next cycle',
};

export const APPLY_HELP: Record<ApplyMode, string> = {
  reload: 'Saving regenerates the proxy configuration and reloads it.',
  dns: 'The DNS service restarts within about 2 seconds of the save. Devices may keep cached answers for a while.',
  waf: 'Sent to the running WAF when you save; the result says whether the WAF took it. The backend sends the stored value again every 30 seconds until the WAF matches.',
  live: 'Read on every use: in effect as soon as it is saved.',
  daily: 'Applied by the daily log cleanup.',
  cycle: 'Read by the blocklist refresh worker when its current wait ends: within 30 minutes while refresh is off, otherwise after the running interval.',
  provider_cycle: 'Read by the egress provider refresh worker when its current wait ends: after the running interval, even when egress default-deny is off.',
};

export const APPLY_MODE: Record<string, ApplyMode> = {
  enable_proxy_auth: 'reload',
  proxy_auth_username: 'reload',
  proxy_auth_password: 'reload',
  enable_time_restrictions: 'reload',
  time_restriction_start: 'reload',
  time_restriction_end: 'reload',
  enable_bandwidth_limits: 'reload',
  bandwidth_limit_mbps: 'reload',
  bandwidth_limit_per_user_kbps: 'reload',
  egress_default_deny: 'reload',
  egress_provider_refresh_hours: 'provider_cycle',
  enable_content_filtering: 'reload',
  blocked_file_types: 'reload',
  enable_safesearch: 'dns',
  enable_youtube_restricted: 'dns',
  auto_refresh_enabled: 'cycle',
  auto_refresh_hours: 'cycle',
  waf_h_entropy: 'waf',
  waf_h_beaconing: 'waf',
  waf_h_pii: 'waf',
  waf_h_sharding: 'waf',
  waf_h_ghosting: 'waf',
  waf_h_sequence: 'waf',
  ssl_bump_enabled: 'reload',
  enable_notifications: 'live',
  notify_waf_block: 'live',
  notify_login_failure: 'live',
  notify_min_level: 'live',
  notify_group_window_minutes: 'live',
  notify_max_per_hour: 'live',
  telegram_bot_token: 'live',
  telegram_chat_id: 'live',
  gotify_url: 'live',
  gotify_token: 'live',
  ntfy_url: 'live',
  ntfy_topic: 'live',
  teams_webhook_url: 'live',
  webhook_url: 'live',
  webhook_bearer_token: 'live',
  gdpr_mode: 'live',
  log_retention_days: 'daily',
  cache_size: 'reload',
  memory_cache: 'reload',
  extra_ssl_ports: 'reload',
  aggressive_caching_enabled: 'reload',
  enable_offline_mode: 'reload',
  cache_bypass_domains: 'reload',
};

/** What each key is called on the page, for messages that name a field. */
export const FIELD_LABELS: Record<string, string> = {
  enable_proxy_auth: 'Require proxy login',
  proxy_auth_username: 'Proxy username',
  proxy_auth_password: 'Proxy password',
  enable_time_restrictions: 'Allowed hours',
  time_restriction_start: 'From',
  time_restriction_end: 'Until',
  enable_bandwidth_limits: 'Bandwidth limits',
  bandwidth_limit_mbps: 'Whole network (Mbps)',
  bandwidth_limit_per_user_kbps: 'Each client (kbps)',
  egress_default_deny: 'Only allowlisted destinations',
  egress_provider_refresh_hours: 'Refresh provider lists every (hours)',
  enable_content_filtering: 'Block risky downloads',
  blocked_file_types: 'Blocked extensions',
  enable_safesearch: 'SafeSearch',
  enable_youtube_restricted: 'YouTube restricted mode',
  auto_refresh_enabled: 'Refresh imported lists',
  auto_refresh_hours: 'Every (hours)',
  waf_h_entropy: 'Entropy detection',
  waf_h_beaconing: 'Beaconing',
  waf_h_pii: 'Personal data in uploads',
  waf_h_sharding: 'Destination sharding',
  waf_h_ghosting: 'Protocol ghosting',
  waf_h_sequence: 'Sequence validation',
  ssl_bump_enabled: 'HTTPS inspection',
  enable_notifications: 'Send alerts',
  notify_waf_block: 'WAF blocks',
  notify_login_failure: 'Failed sign-ins',
  notify_min_level: 'Minimum level',
  notify_group_window_minutes: 'Group window (minutes)',
  notify_max_per_hour: 'Alerts per channel per hour',
  webhook_url: 'Webhook URL',
  webhook_bearer_token: 'Bearer token',
  telegram_bot_token: 'Bot token',
  telegram_chat_id: 'Chat ID',
  gotify_url: 'Gotify URL',
  gotify_token: 'App token',
  ntfy_url: 'ntfy server URL',
  ntfy_topic: 'ntfy topic',
  teams_webhook_url: 'Teams webhook URL',
  gdpr_mode: 'Mask client IPs',
  log_retention_days: 'Keep logs for (days)',
  proxy_port: 'Proxy port',
  cache_size: 'Disk cache (MB)',
  memory_cache: 'Memory cache (MB)',
  extra_ssl_ports: 'Extra HTTPS ports',
  aggressive_caching_enabled: 'Cache static files longer',
  enable_offline_mode: 'Offline mode',
  cache_bypass_domains: 'Never cache these domains',
};

export function fieldLabel(key: string): string {
  return FIELD_LABELS[key] ?? key;
}
