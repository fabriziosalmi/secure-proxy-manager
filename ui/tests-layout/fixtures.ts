/**
 * Fixed API answers for the layout suite: the counts of a real install with
 * made-up private addresses, so every page renders the text lengths, counts
 * and dates it shows in use. Every /api request is answered here;
 * one this file does not know gets a 404 and is listed by the test that
 * hit it, never forwarded to a backend.
 */
import type { Page, Route } from '@playwright/test';

/** 08:52:30 in Europe/Rome (UTC+1 after 25 October 2026). */
export const NOW = new Date('2026-10-29T07:52:30Z');
export const TIME_ZONE = 'Europe/Rome';

type Json = unknown;
const ok = (data: Json): Json => ({ status: 'success', data });
const list = (data: Json[], meta: Record<string, number>): Json => ({ status: 'success', data, meta });
const r = (reason: string, label: string, count: number) => ({ reason, label, count });

const timeline = Array.from({ length: 25 }, (_, i) => {
  const key = new Date(Date.UTC(2026, 9, 28, 7 + i)).toISOString().slice(0, 13).replace('T', ' ') + ':00:00';
  const total = i === 0 ? 3 : i === 24 ? 120 : 60 + ((i * 37) % 140);
  return { time: key, total, blocked: Math.min(total, i % 4 === 0 ? 8 : 2) };
});

const domainAcl = { names: 77515, limit: 200000, held: true, written_at: 1761696000 };

const summary = {
  total_requests: 6539, blocked_requests: 145, today_requests: 500, today_blocked: 10,
  last_24h_requests: 2357, last_24h_blocked: 97, last_24h_clients: 3,
  last_24h_internal_sources: 1, last_24h_internal_requests: 40,
  last_request_at: '2026-10-29 07:51:30',
  top_blocked: [
    { dest: 'iadsdk.apple.com', count: 31, reasons: [r('domain_blacklist', 'Domain blacklist (proxy)', 31)] },
    { dest: 'mtalk.google.com:5228', count: 27, reasons: [r('port_policy', 'Port policy', 27)] },
    { dest: 'github.com', count: 24, reasons: [r('domain_blacklist', 'Domain blacklist (proxy)', 20), r('domain_blacklist_dns', 'Domain blacklist (DNS sinkhole)', 4)] },
  ],
  top_clients: [{ ip: '10.20.0.109', count: 2300 }, { ip: '10.20.0.20', count: 50 }, { ip: '10.20.0.30', count: 7 }],
  threat_categories: [],
  blocked_by_reason_24h: [r('domain_blacklist', 'Domain blacklist (proxy)', 66), r('port_policy', 'Port policy', 27), r('domain_blacklist_dns', 'Domain blacklist (DNS sinkhole)', 4)],
  recent_blocks: [
    { timestamp: '2026-10-29 00:34:30', source_ip: '10.20.0.109', method: 'CONNECT', destination: 'iadsdk.apple.com:443', host: 'iadsdk.apple.com', status: 'TCP_DENIED/403', reason: 'domain_blacklist', reason_label: 'Domain blacklist (proxy)' },
    { timestamp: '2026-10-28 22:51:10', source_ip: '10.20.0.109', method: 'CONNECT', destination: 'github.com:443', host: 'github.com', status: 'TCP_DENIED/403', reason: 'domain_blacklist', reason_label: 'Domain blacklist (proxy)' },
    { timestamp: '2026-10-28 22:43:05', source_ip: '10.20.0.109', method: 'CONNECT', destination: 'iadsdk.apple.com:443', host: 'iadsdk.apple.com', status: 'TCP_DENIED/403', reason: 'domain_blacklist', reason_label: 'Domain blacklist (proxy)' },
  ],
  ip_blacklist_count: 50772, domain_blacklist_count: 77569,
  squid_domain_acl: domainAcl,
  waf: {
    total_requests: 1672, total_blocked: 0, avg_url_entropy: 3, high_entropy_count: 0, requests_last_minute: 1,
    top_blocked_categories: [{ key: 'SQL_INJECTION', count: 6 }, { key: 'DGA_DOMAIN', count: 6 }, { key: 'RANSOMWARE', count: 4 }, { key: 'HEURISTIC_BEACONING', count: 1 }],
  },
  waf_status: 'ok',
};

const days = ['2026-10-23', '2026-10-24', '2026-10-25', '2026-10-26', '2026-10-27', '2026-10-28', '2026-10-29'];
const perDay = [0, 0, 8, 10, 8, 110, 9];
const blockedByDay = {
  tz: TIME_ZONE,
  internal_sources: 2,
  days: days.map((date, i) => {
    const n = perDay[i];
    const dns = Math.ceil(n * 0.3);
    const proxy = Math.floor(n * 0.5);
    const reasons = n === 0 ? [] : i === 2
      ? [r('unclassified', 'Unclassified (no reason recorded)', n)]
      : [r('domain_blacklist_dns', 'Domain blacklist (DNS sinkhole)', dns), r('domain_blacklist', 'Domain blacklist (proxy)', proxy), r('port_policy', 'Port policy', n - dns - proxy)];
    return { date, start: 0, end: 0, blocked: n, reasons };
  }),
  reasons: [r('domain_blacklist', 'Domain blacklist (proxy)', 70), r('domain_blacklist_dns', 'Domain blacklist (DNS sinkhole)', 37), r('port_policy', 'Port policy', 30), r('unclassified', 'Unclassified (no reason recorded)', 8)],
};

const coverage = {
  domain_blacklist: { entries: 77569, squid_acl: domainAcl },
  ip_blacklist: { entries: 50772, squid_acl: { entries: 50772, networks: 32215, dropped: 0, written_at: 1761693300 } },
  waf: { status: 'ok', categories: 21, categories_enabled: 21, rules: 172, rules_enabled: 172 },
  https_inspection: false, proxy_login: false, proxy_login_status: { state: 'off', users: 0, written_at: 0 },
  alerts: { enabled: false, channels: 0, waf_alerts_delivered: true },
};

const clients = {
  data: [
    { ip_address: '10.20.0.109', requests: 6539, blocked: 145, last_seen: '2026-10-29 07:51:30', status: 'Active', internal: false, kind: 'Private network address' },
    { ip_address: '10.20.0.20', requests: 400, blocked: 0, last_seen: '2026-10-25 22:55:00', status: 'Active', internal: false, kind: 'Private network address' },
    { ip_address: '10.20.0.30', requests: 12, blocked: 0, last_seen: '2026-10-25 22:55:10', status: 'Active', internal: false, kind: 'Private network address' },
    { ip_address: '172.18.0.1', requests: 99, blocked: 0, last_seen: '2026-10-29 07:50:00', status: 'Active', internal: true, kind: 'Internal: this host' },
    { ip_address: '127.0.0.1', requests: 9, blocked: 0, last_seen: '2026-10-29 07:50:00', status: 'Active', internal: true, kind: 'Internal: loopback, from inside the proxy container' },
  ],
  meta: { total: 3, limit: 50, offset: 0, internal: 2 },
};

const clientDetail = {
  ip_address: '10.20.0.109', internal: false, kind: 'Private network address', total_requests: 6539, blocked: 145,
  first_seen: '2026-10-25 07:59:02', last_seen: '2026-10-29 07:51:30',
  top_domains: [
    { destination: 'updates.cdn-apple.com', requests: 602, blocked: 0 },
    { destination: 'gdmf.apple.com', requests: 398, blocked: 0 },
    { destination: 'github.com', requests: 40, blocked: 24 },
  ],
  recent: [{ timestamp: '2026-10-29 07:51:30', method: 'CONNECT', destination: 'clientservices.googleapis.com:443', status: 'TCP_TUNNEL/200', bytes: 3072, blocked: false, reason: 'none', reason_label: 'Allowed' }],
  blocked_by_reason: [r('domain_blacklist', 'Domain blacklist (proxy)', 100), r('unclassified', 'Unclassified (no reason recorded)', 8)],
};

const logRows = [3072, 7066, 4096, 6963, 7168, 3379].map((bytes, i) => ({
  id: 1000 - i, timestamp: `2026-10-29 07:51:${String(30 - i).padStart(2, '0')}`, source_ip: '10.20.0.109', method: 'CONNECT',
  destination: 'clientservices.googleapis.com:443', status: 'TCP_TUNNEL/200', bytes, blocked: false, reason: 'none', reason_label: 'Allowed',
  internal: false, kind: 'Private network address', resolved_ip: '142.250.180.10',
})).concat([{
  id: 990, timestamp: '2026-10-28 22:51:10', source_ip: '10.20.0.109', method: 'CONNECT', destination: 'github.com:443', status: 'TCP_DENIED/403',
  bytes: 3900, blocked: true, reason: 'domain_blacklist', reason_label: 'Domain blacklist (proxy)', internal: false, kind: 'Private network address', resolved_ip: null as unknown as string,
}]);

const enforcement = {
  dns_blocklist_limit: 1000000, domain_blacklist_entries: 77569, domain_blacklist_on_allowed: 0,
  squid_domain_acl: domainAcl,
  squid_ip_blacklist: { entries: 50772, networks: 32215, dropped: 0, written_at: Math.floor(Date.UTC(2026, 9, 28, 23, 15) / 1000) },
  squid_ip_whitelist: null,
};

const listTotals: Record<string, number> = { 'ip-blacklist': 50772, 'domain-blacklist': 77569, 'ip-whitelist': 0, 'domain-whitelist': 22 };
const ipEntries = Array.from({ length: 50 }, (_, i) => ({
  id: i + 1, ip: `220.158.${(216 + i) % 256}.0/22`, description: null, added_date: '2026-10-25 08:02:00', source_id: null, source_kind: null,
}));
const docker = ['docker.com', 'hub.docker.com', 'registry.docker.io', 'auth.docker.io', 'production.cloudflare.docker.com'];
const allowedEntries = docker.map((domain, i) => ({ id: i + 1, domain, description: 'Essential: Docker', added_date: '2026-10-28 13:26:00', source_id: 9, source_kind: 'manual' }));
const listEntries: Record<string, Json[]> = { 'ip-blacklist': ipEntries, 'domain-blacklist': [], 'ip-whitelist': [], 'domain-whitelist': allowedEntries };

const listSources: Record<string, Json[]> = {
  'ip-blacklist': [{ id: null, kind: 'unrecorded', source: '', label: '', entries: 50772, first_added: '2026-10-25 08:00:00', last_added: '2026-10-25 08:02:00' }],
  'domain-blacklist': [
    { id: 1, kind: 'url', source: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', label: 'StevenBlack Unified', entries: 62841, first_added: '2026-10-28 13:25:00', last_added: '2026-10-28 13:25:40' },
    { id: 2, kind: 'url', source: 'https://someonewhocares.org/hosts/zero/hosts', label: 'DanPollock Hosts', entries: 12902, first_added: '2026-10-28 13:26:00', last_added: '2026-10-28 13:26:10' },
    { id: 3, kind: 'url', source: 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt', label: 'URLhaus Malware', entries: 1826, first_added: '2026-10-28 13:26:20', last_added: '2026-10-28 13:26:21' },
  ],
  'ip-whitelist': [],
  'domain-whitelist': [{ id: 9, kind: 'manual', source: '', label: '', entries: 22, first_added: '2026-10-28 13:26:00', last_added: '2026-10-28 13:26:30' }],
};

const settings = [
  ['wizard_completed', 'true'], ['default_password_changed', 'false'], ['ssl_bump_enabled', 'false'],
  ['enable_notifications', 'false'], ['enable_proxy_auth', 'false'], ['egress_default_deny', 'false'],
  ['proxy_port', '3128'], ['enable_content_filtering', 'false'], ['egress_provider_refresh_hours', '24'],
].map(([setting_name, setting_value]) => ({ setting_name, setting_value }));

const providers = ['amazon', 'cloudflare', 'digitalocean'].map((name, i) => ({
  id: i + 1, kind: 'catalog', name, url: '', source: name === 'amazon' ? 'ip-ranges.amazonaws.com' : `${name}.com`, enabled: false,
  shared_network: true, v4_count: 0, v6_count: 0, ipv4_covered: 0, ipv6_64_covered: 0, last_refresh: '', last_commit: '', last_error: '', held: null,
}));

const audit = [
  { id: 10, username: 'admin', action: 'login', target: '10.20.0.134', details: null, timestamp: '2026-10-29 07:52:31' },
  { id: 9, username: 'admin', action: 'update_settings', target: 'auto_refresh_hours,egress_default_deny,egress_provider_refresh_hours,enable_content_filtering,blocked_file_types,enable_safesearch,enable_youtube_restricted,auto_refresh_enabled', details: '', timestamp: '2026-10-28 13:28:00' },
  { id: 8, username: 'admin', action: 'egress_provider_disabled', target: 'telegram', details: '{"kind":"catalog"}', timestamp: '2026-10-28 13:27:30' },
  { id: 7, username: 'admin', action: 'egress_provider_enabled', target: 'telegram', details: '{"kind":"catalog","shared_network":false}', timestamp: '2026-10-28 13:27:20' },
  ...docker.map((target, i) => ({ id: 6 - i, username: 'admin', action: 'add_domain_whitelist', target, details: 'Essential: Docker', timestamp: '2026-10-28 13:26:00' })),
];

/** The answer to one API path and query, or undefined when the suite does not know it. */
export function answer(url: URL): Json | undefined {
  const p = url.pathname.replace(/^\/api\//, '');
  const lists = /^(ip|domain)-(blacklist|whitelist)$/;
  const sourcesOf = /^((?:ip|domain)-(?:blacklist|whitelist))\/sources$/;
  switch (p) {
    case 'session': return ok({ username: 'admin', expires_at: Math.floor(NOW.getTime() / 1000) + 3600 });
    case 'settings': return ok(settings);
    case 'status': return ok({ proxy_status: 'running', backend_status: 'running', proxy_port: '3128', version: '3.18.3' });
    case 'health': return { status: 'healthy', version: '3.18.3' };
    case 'dashboard/summary': return ok(summary);
    case 'logs/timeline': return ok(timeline);
    case 'cache/statistics': return ok({ state: 'not_collected', collected_at: null, age_s: null });
    case 'analytics/blocked-by-day': return ok(blockedByDay);
    case 'analytics/coverage': return ok(coverage);
    case 'analytics/shadow-it': return ok([
      { name: 'iCloud', domain: 'icloud.com', requests: 397, category: 'File Sharing' },
      { name: 'Tailscale', domain: 'tailscale.com', requests: 9, category: 'Tunneling' },
      { name: 'Facebook', domain: 'facebook.com', requests: 4, category: 'Social' },
    ]);
    case 'analytics/user-agents': return ok({ methods: [], service_types: [{ name: 'Apple', count: 4445 }, { name: 'Other', count: 3086 }, { name: 'Google Services', count: 418 }] });
    case 'analytics/file-extensions': return ok({ extensions: [], categories: [], examined: 0, limit: 10000 });
    case 'clients/statistics': return { status: 'success', ...clients };
    case 'logs/stats': return ok({ total_count: 6539, blocked_count: 145, blocked_by_reason: [r('domain_blacklist', 'Domain blacklist (proxy)', 100)] });
    case 'logs': return list(logRows, { total: 6539, limit: 100, offset: 0, internal: 120 });
    case 'blacklists/enforcement': return ok(enforcement);
    case 'egress-allowlist': return list([], { total: 0, limit: 50, offset: 0 });
    case 'egress-providers': return ok(providers);
    case 'audit-log': return list(audit, { total: audit.length, limit: 50, offset: 0, retention_days: 365 });
  }
  if (/^clients\/.+\/details$/.test(p)) return ok(clientDetail);
  const src = sourcesOf.exec(p);
  if (src) return ok(listSources[src[1]] ?? []);
  if (lists.test(p)) {
    const limit = Number(url.searchParams.get('limit') || 50);
    return list((listEntries[p] ?? []).slice(0, limit), { total: listTotals[p] ?? 0, limit, offset: 0 });
  }
  return undefined;
}

/**
 * Answers every /api request of page from the fixtures, freezes its clock at
 * NOW, and returns the API paths it asked for that the fixtures do not know.
 */
export async function mockApi(page: Page): Promise<Set<string>> {
  const unknown = new Set<string>();
  await page.clock.setFixedTime(NOW);
  await page.route('**/api/**', async (route: Route) => {
    const url = new URL(route.request().url());
    // The live feed of the access log is not laid out by this suite: its
    // token request is refused, and the page shows it as reconnecting.
    if (url.pathname === '/api/ws-token') {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"status":"error"}' });
      return;
    }
    const body = answer(url);
    if (body === undefined) {
      unknown.add(url.pathname);
      await route.fulfill({ status: 404, contentType: 'application/json', body: '{"status":"error"}' });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  return unknown;
}
