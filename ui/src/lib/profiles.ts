/**
 * Profiles: one click that sets several sections at once. Trimmed to keys
 * that are enforced: no WAF threshold, direct-IP or auth method (nothing
 * reads them), no offline mode or aggressive caching (Proxy engine, and
 * not verified to work), no kiosk_mode (no reader). A profile always sends
 * a toggle together with its parameters.
 */
import { sectionOfKey, fieldLabel, SECTIONS, type SectionId } from './settingsMeta';

export interface Profile {
  id: string;
  name: string;
  summary: string;
  values: Record<string, string>;
}

const HEURISTICS_ALL = { waf_h_entropy: 'true', waf_h_beaconing: 'true', waf_h_pii: 'true', waf_h_sharding: 'true', waf_h_ghosting: 'true' };
const OPEN_ACCESS = { enable_bandwidth_limits: 'false', enable_time_restrictions: 'false', enable_proxy_auth: 'false' };
const NO_FILTERS = { enable_safesearch: 'false', enable_youtube_restricted: 'false', enable_content_filtering: 'false' };
const RISKY = 'exe,bat,cmd,dll,msi,scr,ps1,vbs';
// No js: the pattern matches any URL path that ends in .js, which is every
// script a web page loads over plain HTTP or under HTTPS inspection.
const RISKY_ALL = 'exe,bat,cmd,dll,msi,scr,ps1,vbs,sh,py,rb,zip,7z,rar,tar,iso';

export const PROFILES: Profile[] = [
  {
    id: 'basic',
    name: 'Basic',
    summary: 'No filters and no HTTPS inspection; one WAF heuristic (entropy).',
    values: {
      ssl_bump_enabled: 'false', ...NO_FILTERS, ...OPEN_ACCESS,
      waf_h_entropy: 'true', waf_h_beaconing: 'false', waf_h_pii: 'false', waf_h_sharding: 'false', waf_h_ghosting: 'false',
    },
  },
  {
    id: 'family',
    name: 'Family',
    summary: 'SafeSearch and YouTube restricted mode, risky downloads blocked, 10 Mbps for the network and 500 kbps per device.',
    values: {
      ssl_bump_enabled: 'false',
      enable_safesearch: 'true', enable_youtube_restricted: 'true',
      enable_content_filtering: 'true', blocked_file_types: RISKY,
      enable_bandwidth_limits: 'true', bandwidth_limit_mbps: '10', bandwidth_limit_per_user_kbps: '500',
      enable_time_restrictions: 'false', enable_proxy_auth: 'false',
      waf_h_entropy: 'true', waf_h_beaconing: 'true', waf_h_pii: 'true', waf_h_sharding: 'false', waf_h_ghosting: 'false',
    },
  },
  {
    id: 'standard',
    name: 'Standard',
    summary: 'Risky downloads blocked, five WAF heuristics on, no limits on who or when.',
    values: {
      ssl_bump_enabled: 'false', enable_safesearch: 'false', enable_youtube_restricted: 'false',
      enable_content_filtering: 'true', blocked_file_types: RISKY,
      ...OPEN_ACCESS, ...HEURISTICS_ALL,
    },
  },
  {
    id: 'devops',
    name: 'DevOps',
    summary: 'Downloads allowed (developers fetch binaries), five WAF heuristics on.',
    values: { ssl_bump_enabled: 'false', ...NO_FILTERS, ...OPEN_ACCESS, ...HEURISTICS_ALL },
  },
  {
    id: 'paranoid',
    name: 'Paranoid',
    summary: 'HTTPS inspection, proxy login, every filter, archives and scripts blocked, 50 Mbps and 2,000 kbps per device.',
    values: {
      ssl_bump_enabled: 'true',
      enable_safesearch: 'true', enable_youtube_restricted: 'true',
      enable_content_filtering: 'true', blocked_file_types: RISKY_ALL,
      enable_bandwidth_limits: 'true', bandwidth_limit_mbps: '50', bandwidth_limit_per_user_kbps: '2000',
      enable_time_restrictions: 'false', enable_proxy_auth: 'true',
      ...HEURISTICS_ALL,
    },
  },
  {
    id: 'kiosk',
    name: 'Kiosk',
    summary: 'For a public terminal: proxy login, open 08:00 to 18:00, every filter, archives and scripts blocked, 10 Mbps.',
    values: {
      ssl_bump_enabled: 'false',
      enable_safesearch: 'true', enable_youtube_restricted: 'true',
      enable_content_filtering: 'true', blocked_file_types: RISKY_ALL,
      enable_bandwidth_limits: 'true', bandwidth_limit_mbps: '10', bandwidth_limit_per_user_kbps: '500',
      enable_time_restrictions: 'true', time_restriction_start: '08:00', time_restriction_end: '18:00',
      enable_proxy_auth: 'true',
      ...HEURISTICS_ALL,
    },
  },
];

/**
 * Turning these on changes what every client experiences at once: HTTPS
 * certificate errors until the CA is installed, a login prompt, refusals
 * outside the window.
 */
const DANGEROUS_WHEN_ON: Record<string, string> = {
  ssl_bump_enabled: 'Every HTTPS site shows a certificate error on a device without the proxy CA.',
  enable_proxy_auth: 'Every device must sign in with the proxy username and password set under Clients and access, or gets 407. Without them every client is refused.',
  enable_time_restrictions: 'Every client is refused outside the window.',
};

export interface ProfileChange {
  key: string;
  label: string;
  section: SectionId;
  from: string | undefined;
  to: string;
  warning?: string;
}

/** What applying a profile would change, grouped in section order. */
export function profileChanges(profile: Profile, stored: Record<string, string>): ProfileChange[] {
  const changes: ProfileChange[] = [];
  for (const [key, to] of Object.entries(profile.values)) {
    const from = stored[key];
    if (from === to) continue;
    const section = sectionOfKey(key);
    if (!section) continue;
    changes.push({ key, label: fieldLabel(key), section, from, to, warning: to === 'true' ? DANGEROUS_WHEN_ON[key] : undefined });
  }
  const order = SECTIONS.map((s) => s.id);
  return changes.sort((a, b) => order.indexOf(a.section) - order.indexOf(b.section));
}

/** The profile the stored values already match, if any. */
export function matchingProfile(stored: Record<string, string>): Profile | undefined {
  return PROFILES.find((p) => Object.entries(p.values).every(([k, v]) => stored[k] === v));
}

/** How a value reads in the preview. */
export function showValue(v: string | undefined): string {
  if (v === undefined || v === '') return 'not set';
  if (v === 'true') return 'on';
  if (v === 'false') return 'off';
  return v;
}
