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

const port: Check = (v) => {
  const n = Number(v);
  return /^[0-9]+$/.test(v) && n >= 1 && n <= 65535 ? undefined : 'must be a port between 1 and 65535';
};

const TIME = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;

const CHECKS: Record<string, Check> = {
  proxy_port: port,
  // The generator reads at most 7 digits for the disk cache and 6 for memory.
  cache_size: (v) => (digits(v, 7) ? undefined : 'must be a whole number of megabytes, at most 7 digits'),
  memory_cache: (v) => (digits(v, 6) ? undefined : 'must be a whole number of megabytes, at most 6 digits'),
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
};

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
 * A backend 400 names the key it refused: "bandwidth_limit_mbps: must be a
 * positive number" (validateSettingValue). Null when the detail names none.
 */
export function parseFieldError(detail: unknown): { key: string; message: string } | null {
  if (typeof detail !== 'string') return null;
  const m = /^([a-z0-9_]+): (.+)$/.exec(detail);
  return m ? { key: m[1], message: m[2] } : null;
}
