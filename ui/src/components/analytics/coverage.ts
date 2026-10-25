/**
 * The lines of "Protection coverage", from GET /api/analytics/coverage: what
 * is switched on and enforced now, each with the place it is changed. A
 * value the backend could not read says so; it is never shown as off.
 */
import type { Coverage } from '../../types';
import { formatCount } from '../../lib/format';
import { sectionPath, type SectionId } from '../../lib/settingsMeta';

/** on: switched on and enforced. off: switched off. attention: on but not fully working, or off where that leaves a gap. unknown: not reported. */
export type CoverageState = 'on' | 'off' | 'attention' | 'unknown';

export interface CoverageLine {
  id: 'domain' | 'ip' | 'waf' | 'https' | 'login' | 'alerts';
  state: CoverageState;
  text: string;
  link: { label: string; to: string };
}

/** Where a Settings section opens: one URL per section. */
export function settingsPath(section: Extract<SectionId, 'inspection' | 'access' | 'alerts'>): string {
  return sectionPath(section);
}

const BLACKLISTS = { label: 'Blacklists', to: '/blacklists' };

function entries(n: number): string {
  return `${formatCount(n)} ${n === 1 ? 'entry' : 'entries'}`;
}

function domainLine(c: Coverage['domain_blacklist']): CoverageLine {
  const base = { id: 'domain' as const, link: BLACKLISTS };
  if (c.entries === null) return { ...base, state: 'unknown', text: 'Domain blacklist: the backend could not count its entries' };
  if (c.entries === 0) return { ...base, state: 'off', text: 'Domain blacklist: empty, no domain is blocked' };
  const head = `Domain blacklist: ${entries(c.entries)}, blocked at the DNS sinkhole`;
  const acl = c.squid_acl;
  if (!acl) return { ...base, state: 'on', text: `${head}; the proxy has not reported whether it holds its own copy` };
  if (acl.held) return { ...base, state: 'on', text: `${head} and by the proxy's own copy` };
  if (acl.names > acl.limit) {
    return { ...base, state: 'attention', text: `${head} only: ${formatCount(acl.names)} names are above the proxy's limit of ${formatCount(acl.limit)}` };
  }
  return { ...base, state: 'attention', text: `${head} only: the proxy could not load its own copy` };
}

function ipLine(c: Coverage['ip_blacklist']): CoverageLine {
  const base = { id: 'ip' as const, link: BLACKLISTS };
  if (c.entries === null) return { ...base, state: 'unknown', text: 'IP blacklist: the backend could not count its entries' };
  if (c.entries === 0) return { ...base, state: 'off', text: 'IP blacklist: empty, no address is blocked' };
  return { ...base, state: 'on', text: `IP blacklist: ${entries(c.entries)}, enforced by the proxy` };
}

function wafLine(c: Coverage): CoverageLine {
  const base = { id: 'waf' as const, link: { label: 'Inspection', to: settingsPath('inspection') } };
  const w = c.waf;
  if (w.status === 'auth_failed') return { ...base, state: 'attention', text: 'WAF: refuses the backend credential, so its rules are not reported (INTERNAL_ALERT_TOKEN must match)' };
  if (w.status === 'unreachable') return { ...base, state: 'attention', text: 'WAF: did not answer the backend, so its rules are not reported' };
  if (w.status !== 'ok' || w.rules === null || w.rules_enabled === null || w.categories === null || w.categories_enabled === null) {
    return { ...base, state: 'attention', text: 'WAF: answered with an error, so its rules are not reported' };
  }
  const scope = c.https_inspection ? 'plain HTTP and inspected HTTPS' : 'plain HTTP only';
  if (w.rules_enabled === 0) return { ...base, state: 'attention', text: `WAF: every rule category is switched off (${formatCount(w.categories)} categories)` };
  const rules = w.rules_enabled === w.rules
    ? `${formatCount(w.rules)} request rules in ${formatCount(w.categories)} categories`
    : `${formatCount(w.rules_enabled)} of ${formatCount(w.rules)} request rules on, in ${formatCount(w.categories_enabled)} of ${formatCount(w.categories)} categories`;
  return { ...base, state: 'on', text: `WAF: ${rules}, inspecting ${scope}` };
}

function httpsLine(on: boolean | null): CoverageLine {
  const base = { id: 'https' as const, link: { label: 'Inspection', to: settingsPath('inspection') } };
  if (on === null) return { ...base, state: 'unknown', text: 'HTTPS inspection: not reported' };
  return on
    ? { ...base, state: 'on', text: 'HTTPS inspection: on, the WAF sees inside HTTPS' }
    : { ...base, state: 'off', text: 'HTTPS inspection: off, so the WAF does not see inside HTTPS' };
}

function loginLine(on: boolean | null): CoverageLine {
  const base = { id: 'login' as const, link: { label: 'Access', to: settingsPath('access') } };
  if (on === null) return { ...base, state: 'unknown', text: 'Proxy login: not reported' };
  return on
    ? { ...base, state: 'on', text: 'Proxy login: on, a device signs in to use the proxy' }
    : { ...base, state: 'off', text: 'Proxy login: off, any device on an allowed network can use the proxy' };
}

function alertsLine(a: Coverage['alerts']): CoverageLine {
  const base = { id: 'alerts' as const, link: { label: 'Alerts', to: settingsPath('alerts') } };
  if (a.enabled === null || a.channels === null) return { ...base, state: 'unknown', text: 'Alerts: the backend could not read the alert settings' };
  if (!a.enabled) return { ...base, state: 'attention', text: 'Alerts: off, blocks are not reported anywhere' };
  if (a.channels === 0) return { ...base, state: 'attention', text: 'Alerts: on, but no channel is set up, so they go nowhere' };
  const to = `sent to ${formatCount(a.channels)} ${a.channels === 1 ? 'channel' : 'channels'}`;
  if (!a.waf_alerts_delivered) {
    return { ...base, state: 'attention', text: `Alerts: on, ${to}, but WAF block alerts do not arrive: INTERNAL_ALERT_TOKEN is not set` };
  }
  return { ...base, state: 'on', text: `Alerts: on, ${to}` };
}

/** The coverage lines, in the order of the mockup. */
export function coverageLines(c: Coverage): CoverageLine[] {
  return [
    domainLine(c.domain_blacklist),
    ipLine(c.ip_blacklist),
    wafLine(c),
    httpsLine(c.https_inspection),
    loginLine(c.proxy_login),
    alertsLine(c.alerts),
  ];
}
