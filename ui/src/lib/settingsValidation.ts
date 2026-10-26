/**
 * Client-side checks for the Settings sections. They mirror the backend's
 * settingValidators (backend-go/internal/handlers/settings.go) with the same
 * messages, and add the limits of the proxy's config generator, which drops
 * a value it cannot parse without saying so (proxy/generate_squid_conf.sh).
 * The backend stays the authority: its 400 is mapped to the field it names.
 */
import type { SectionId } from './settingsMeta';
import { SECTION_KEYS } from './settingsMeta';

type Check = (value: string, values: Record<string, string>) => string | undefined;

const on = (values: Record<string, string>, key: string) => values[key] === 'true';
const digits = (v: string, max: number) => new RegExp(`^[0-9]{1,${max}}$`).test(v);
const wholeIn = (v: string, lo: number, hi: number) => /^[0-9]+$/.test(v) && Number(v) >= lo && Number(v) <= hi;

const port: Check = (v) => {
  const n = Number(v);
  return /^[0-9]+$/.test(v) && n >= 1 && n <= 65535 ? undefined : 'must be a port between 1 and 65535';
};

const TIME = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;

const CHECKS: Record<string, Check> = {
  proxy_port: port,
  // The generator reads at most 7 digits for the disk cache and 6 for memory.
  cache_size: (v) => (digits(v, 7) && Number(v) >= 1 ? undefined : 'must be a whole number of megabytes, from 1 to 9999999'),
  memory_cache: (v) => (digits(v, 6) && Number(v) >= 1 ? undefined : 'must be a whole number of megabytes, from 1 to 999999'),
  extra_ssl_ports: (v) => {
    if (!/^\s*([0-9]{1,5}([ ,]+[0-9]{1,5})*)?\s*$/.test(v)) return 'must be port numbers separated by commas or spaces';
    for (const p of v.split(/[ ,]+/).filter(Boolean)) if (port(p, {})) return 'must be port numbers separated by commas or spaces';
    return undefined;
  },
  log_retention_days: (v) => (/^[0-9]+$/.test(v) && Number(v) > 0 ? undefined : 'must be a positive number'),
  bandwidth_limit_mbps: (v, values) => {
    if (!on(values, 'enable_bandwidth_limits') && v === '') return undefined;
    // The generator reads at most 6 digits.
    return digits(v, 6) && Number(v) > 0 ? undefined : 'must be a whole number of Mbps, from 1 to 999999';
  },
  bandwidth_limit_per_user_kbps: (v, values) => {
    if (!on(values, 'enable_bandwidth_limits') && v === '') return undefined;
    return digits(v, 9) ? undefined : 'must be a whole number of kbps, 0 for no per-client limit';
  },
  time_restriction_start: (v, values) => {
    if (!on(values, 'enable_time_restrictions') && v === '') return undefined;
    return TIME.test(v) ? undefined : 'must be a time of day as HH:MM';
  },
  time_restriction_end: (v, values) => {
    if (!on(values, 'enable_time_restrictions') && v === '') return undefined;
    if (!TIME.test(v)) return 'must be a time of day as HH:MM';
    // Squid's time ACL needs the window to end after it starts, on the same day.
    const start = values.time_restriction_start ?? '';
    if (on(values, 'enable_time_restrictions') && TIME.test(start) && v <= start) return 'must be later than the start time';
    return undefined;
  },
  auto_refresh_hours: (v, values) => {
    if (!on(values, 'auto_refresh_enabled') && v === '') return undefined;
    // The worker reads anything else as 0 and never refreshes.
    return /^[0-9]+$/.test(v) && Number(v) >= 1 && Number(v) <= 168 ? undefined : 'must be a whole number of hours, from 1 to 168';
  },
  blocked_file_types: (v, values) => {
    const items = v.split(',').map((s) => s.trim()).filter(Boolean);
    if (on(values, 'enable_content_filtering') && items.length === 0) {
      return 'list at least one extension: with an empty list the proxy blocks nothing';
    }
    const bad = items.find((s) => !/^\.?[a-z0-9]{1,10}$/i.test(s));
    return bad ? `"${bad}" is not a file extension: use letters and digits only, such as exe` : undefined;
  },
  // The notification limits (notify_limit.go); the backend reads a value out
  // of range as its default, so it is refused before it is saved and ignored.
  notify_group_window_minutes: (v) => (wholeIn(v, 1, 1440) ? undefined : 'must be a whole number of minutes, from 1 to 1440'),
  notify_max_per_hour: (v) => (wholeIn(v, 1, 1000) ? undefined : 'must be a whole number of alerts, from 1 to 1000'),
  notify_min_level: (v) => (['info', 'warning', 'error'].includes(v) ? undefined : 'must be info, warning or error'),
  cache_bypass_domains: (v) => {
    const bad = v.split(',').map((s) => s.trim()).filter(Boolean).find((d) => !DOMAIN.test(d.replace(/^\*?\./, '')));
    return bad ? `"${bad}" is not a domain name, such as bank.example.com` : undefined;
  },
  proxy_auth_username: (v) => checkProxyUsername(v),
};

/**
 * The proxy login (backend-go/internal/handlers/proxy_login.go). A colon
 * ends the user name in Basic auth and in the password file, and a space
 * ends it in the line Squid sends its helper.
 */
export function checkProxyUsername(v: string): string | undefined {
  return v === '' || /^[A-Za-z0-9._@+-]{1,64}$/.test(v)
    ? undefined
    : 'must be 1 to 64 letters, digits or the characters . _ @ + -, with no spaces or colons';
}

/** Bcrypt, the proxy's password hash, reads at most 72 bytes. */
export function checkProxyPassword(v: string): string | undefined {
  if (v === '') return undefined;
  if (/[\r\n\0]/.test(v)) return 'must be on one line';
  if ([...v].length < 12) return 'must be at least 12 characters';
  if (new TextEncoder().encode(v).length > 72) return "must be at most 72 bytes: the proxy's password hash reads no further";
  return undefined;
}

const NO_CREDENTIALS = ': with proxy login on and no credentials the proxy refuses every client';

/**
 * Login on needs both credentials, as the backend checks: with login on and
 * none set the proxy refuses every client. passwordAfterSave says whether a
 * password will be stored once the section is saved (typed, or stored and
 * not removed).
 */
export function validateProxyLogin(values: Record<string, string>, passwordAfterSave: boolean): Record<string, string> {
  if (!on(values, 'enable_proxy_auth')) return {};
  const errors: Record<string, string> = {};
  if ((values.proxy_auth_username ?? '') === '') errors.proxy_auth_username = `set the username devices sign in with${NO_CREDENTIALS}`;
  if (!passwordAfterSave) errors.proxy_auth_password = `set the password devices sign in with${NO_CREDENTIALS}`;
  return errors;
}

// A DNS name as netguard.IsValidHostname accepts it.
const DOMAIN = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$/i;

/** The alert destinations the backend posts to (netguard.CheckNotifyURL). */
const NOTIFY_URL_KEYS = new Set(['webhook_url', 'gotify_url', 'teams_webhook_url', 'ntfy_url']);

/**
 * The same shape check the backend applies to a notification URL when it is
 * saved: http or https, a host, no credentials, not this host. A name that
 * resolves inside the stack is refused at delivery, where the address is known.
 */
export function checkNotifyUrl(raw: string): string | undefined {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return 'must be an http or https URL, such as https://alerts.example.com/hook';
  }
  if ((u.protocol !== 'http:' && u.protocol !== 'https:') || !u.hostname) return 'must be an http or https URL, such as https://alerts.example.com/hook';
  if (u.username || u.password) return 'must not carry a user name or password: use the token setting instead';
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost')) return 'must not point at this host: use an address the backend can reach on your network';
  if (/^127\./.test(host) || host === '::1' || /^169\.254\./.test(host) || /^fe80:/i.test(host) || host === '0.0.0.0' || /^0\./.test(host) || /^2(2[4-9]|3[0-9])\./.test(host)) {
    return 'must not point at a loopback, link-local or multicast address: use an address the backend can reach on your network';
  }
  return undefined;
}

/** Secrets with a value domain of their own, beyond the notification URLs. */
const SECRET_CHECKS: Record<string, (value: string) => string | undefined> = {
  proxy_auth_password: checkProxyPassword,
};

/** The problems in the secrets a section is about to send (the typed ones only). */
export function validateSecrets(id: SectionId, typed: Record<string, string>): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const [key, value] of Object.entries(typed)) {
    if (!SECTION_KEYS[id].includes(key)) continue;
    const check = NOTIFY_URL_KEYS.has(key) ? checkNotifyUrl : SECRET_CHECKS[key];
    const msg = check?.(value);
    if (msg) errors[key] = msg;
  }
  return errors;
}

/** Parameters a toggle needs: with the toggle on, the value must be there. */
const REQUIRED_WHEN: Record<string, string> = {
  bandwidth_limit_mbps: 'enable_bandwidth_limits',
  bandwidth_limit_per_user_kbps: 'enable_bandwidth_limits',
  time_restriction_start: 'enable_time_restrictions',
  time_restriction_end: 'enable_time_restrictions',
  auto_refresh_hours: 'auto_refresh_enabled',
  blocked_file_types: 'enable_content_filtering',
};

/**
 * The problems in what a section is about to send, by key. sent lists the
 * keys in the request; a key that is not sent (the backend has no value for
 * it and nobody typed one) is checked only when its toggle is on and needs it.
 */
export function validateSection(id: SectionId, values: Record<string, string>, sent: string[]): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const key of SECTION_KEYS[id]) {
    const check = CHECKS[key];
    if (!check) continue;
    const needed = REQUIRED_WHEN[key] !== undefined && on(values, REQUIRED_WHEN[key]);
    if (!sent.includes(key) && !needed) continue;
    const msg = check(values[key] ?? '', values);
    if (msg) errors[key] = msg;
  }
  return errors;
}

/**
 * A backend 400 lists every key it refused in errors {key: message}; an
 * older backend names only the first in detail. Null when neither names one.
 */
export function parseFieldErrors(data: unknown): Record<string, string> | null {
  const d = data as { errors?: unknown; detail?: unknown } | null | undefined;
  if (d && d.errors && typeof d.errors === 'object') {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(d.errors as Record<string, unknown>)) if (typeof v === 'string') out[k] = v;
    if (Object.keys(out).length) return out;
  }
  const one = parseFieldError(d?.detail);
  return one ? { [one.key]: one.message } : null;
}

/**
 * A backend 400 names the key it refused: "bandwidth_limit_mbps: must be a
 * positive number" (validateSettingValue). Null when the detail names none.
 */
export function parseFieldError(detail: unknown): { key: string; message: string } | null {
  if (typeof detail !== 'string') return null;
  const m = /^([a-z0-9_]+): (.+)$/.exec(detail);
  return m ? { key: m[1], message: m[2] } : null;
}

/**
 * The patterns the backend writes for a list of extensions
 * (blockedExtensionPattern in backend-go/internal/handlers/settings.go): the
 * extension at the end of the path, with or without a query string after it.
 */
export function extensionPatterns(list: string): string[] {
  return list
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .map((ext) => `\\${ext.startsWith('.') ? ext : `.${ext}`}(\\?.*)?$`);
}
