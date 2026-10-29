/**
 * The audit log in plain words. The backend records each event as an action
 * key, a target and details (backend-go/internal/handlers/audit.go lists the
 * keys); a list change carries its counts as a JSON object in details. This
 * module turns a row into the sentence the Audit page shows ("Imported 71,140
 * domains from StevenBlack Unified", "Removed all 640,929 blocked domains")
 * and the details beside it.
 *
 * A key this module does not know is shown verbatim, with its target and
 * details as recorded, never guessed at.
 */
import { formatCount, formatDateTime } from './format';
import { fieldLabel } from './settingsMeta';
import { showValue } from './profiles';
import type { AuditEntry } from '../types';

/** Change for anything that changed state; the sign-in kinds for the session events. */
export type AuditKind = 'change' | 'signin' | 'signin-failed';

export interface AuditDescription {
  event: string;
  /** What else the row says, in words; null when it says nothing more. */
  details: string | null;
  kind: AuditKind;
}

interface ListWords {
  label: string;
  one: string;
  many: string;
  /** The noun for what an import adds. */
  imported: [string, string];
}

/** The lists by the name the audit log gives them. */
const LISTS: Record<string, ListWords> = {
  ip_blacklist: { label: 'Blocked IPs', one: 'blocked IP', many: 'blocked IPs', imported: ['IP', 'IPs'] },
  domain_blacklist: { label: 'Blocked domains', one: 'blocked domain', many: 'blocked domains', imported: ['domain', 'domains'] },
  ip_whitelist: { label: 'IP exceptions', one: 'IP exception', many: 'IP exceptions', imported: ['IP', 'IPs'] },
  domain_whitelist: { label: 'Domain exceptions', one: 'domain exception', many: 'domain exceptions', imported: ['domain', 'domains'] },
  egress_allowlist: { label: 'the default-deny allowlist', one: 'egress destination', many: 'egress destinations', imported: ['destination', 'destinations'] },
};

const LIST_NAMES = Object.keys(LISTS).join('|');
const LIST_ACTION = new RegExp(`^(add_preset|add|remove|bulk_remove|clear|import|remove_source|restore)_(${LIST_NAMES})$`);

const SIGN_INS: Record<string, string> = { login: 'Signed in', logout: 'Signed out' };

/** A sign-in or sign-out, from the address it records (none before 3.15.0). */
function describeSignIn(e: AuditEntry, event: string): AuditDescription {
  return { event, details: e.target ? `From ${e.target}` : 'Address not recorded', kind: 'signin' };
}

/** Fixed sentences for the actions that carry no counts. */
const PLAIN: Record<string, string> = {
  change_password: 'Changed the password',
  reload_config: 'Reloaded the proxy configuration',
  clear_cache: 'Cleared the proxy cache',
  clear_logs: 'Cleared the access logs',
  database_reset: 'Reset the database',
  restore_config: 'Restored settings from a backup',
};

type Fields = Record<string, unknown>;

/** The details of a list change, or null when they are not a JSON object. */
function fields(details: string | null): Fields | null {
  if (!details || details[0] !== '{') return null;
  try {
    const v: unknown = JSON.parse(details);
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Fields) : null;
  } catch {
    return null;
  }
}

function num(f: Fields | null, key: string): number | null {
  const v = f?.[key];
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function str(f: Fields | null, key: string): string | null {
  const v = f?.[key];
  return typeof v === 'string' && v !== '' ? v : null;
}

/** "1 blocked domain", "640,929 blocked domains". */
function count(n: number, one: string, many: string): string {
  return `${formatCount(n)} ${n === 1 ? one : many}`;
}

function join(parts: (string | null | undefined | false)[]): string | null {
  const kept = parts.filter((p): p is string => typeof p === 'string' && p !== '');
  return kept.length ? kept.join('. ') : null;
}

/** A JSON object of details as "key: value" pairs; anything else as recorded. */
function readable(details: string | null): string | null {
  const f = fields(details);
  if (!f) return details || null;
  const parts = Object.entries(f).map(([k, v]) => `${k.replace(/_/g, ' ')}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`);
  return parts.length ? parts.join(', ') : null;
}

/**
 * The row as recorded, for a key this module does not know: the key in words
 * ("some_new_event" reads "Some new event"), its target, and its details as
 * fields. The raw key and JSON used to be shown as they were.
 */
function verbatim(e: AuditEntry): AuditDescription {
  const words = (e.action || '').replace(/_/g, ' ').trim();
  const event = words ? words.charAt(0).toUpperCase() + words.slice(1) : 'No action recorded';
  return { event, details: join([e.target, readable(e.details)]), kind: 'change' };
}

/** A setting by its label on the Settings page, or its key in words when it has none. */
function settingName(key: string): string {
  const label = fieldLabel(key);
  if (label !== key) return label;
  const words = key.replace(/_/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** "Send alerts: off to on; Telegram bot token: set": what a settings save changed, from its details. */
function settingChanges(f: Fields | null): string | null {
  if (!f) return null;
  const parts: string[] = [];
  const changes = f.changes && typeof f.changes === 'object' ? (f.changes as Record<string, Fields>) : {};
  for (const [key, c] of Object.entries(changes)) {
    const from = typeof c?.from === 'string' ? c.from : undefined;
    const to = typeof c?.to === 'string' ? c.to : undefined;
    parts.push(`${settingName(key)}: ${showValue(from)} to ${showValue(to)}${c?.truncated ? ' (cut)' : ''}`);
  }
  const secrets = f.secrets && typeof f.secrets === 'object' ? (f.secrets as Record<string, unknown>) : {};
  for (const [key, state] of Object.entries(secrets)) parts.push(`${settingName(key)}: ${state === 'cleared' ? 'cleared' : 'set'}`);
  return parts.length ? parts.join('; ') : null;
}

/** The egress provider events (backend handlers and workers, egress_providers.go). */
function describeProvider(e: AuditEntry, action: string): AuditDescription | null {
  const f = fields(e.details);
  const name = e.target || 'a provider';
  const what = str(f, 'kind') === 'url' ? `the URL list ${name}` : `the provider list ${name}`;
  const range = (before: string, after: string, label: string) => {
    const a = num(f, before);
    const b = num(f, after);
    return a !== null && b !== null ? `${label} ${formatCount(a)} to ${formatCount(b)}` : null;
  };
  const commit = str(f, 'commit');
  switch (action) {
    case 'egress_provider_enabled':
      return { event: `Turned on ${what}`, details: join([str(f, 'url'), f?.shared_network === true ? 'A shared network' : null]), kind: 'change' };
    case 'egress_provider_disabled':
      return { event: f?.deleted === true ? `Removed ${what}` : `Turned off ${what}`, details: str(f, 'url'), kind: 'change' };
    case 'egress_provider_refreshed':
      return {
        event: `Downloaded ${what}`,
        details: join([range('v4_before', 'v4_after', 'IPv4 prefixes'), range('v6_before', 'v6_after', 'IPv6 prefixes'), commit && `Commit ${commit.slice(0, 7)}`]),
        kind: 'change',
      };
    case 'egress_provider_refresh_failed':
      return { event: `Could not download ${what}`, details: str(f, 'reason'), kind: 'change' };
    case 'egress_provider_held':
      return { event: `Held an update of ${what} for review`, details: join([str(f, 'reason'), range('v4_before', 'v4_after', 'IPv4 prefixes')]), kind: 'change' };
    case 'egress_provider_held_applied':
      return { event: `Applied the held update of ${what}`, details: range('v4_before', 'v4_after', 'IPv4 prefixes'), kind: 'change' };
  }
  return null;
}

/** Where a removed source's entries came from, as the end of a sentence. */
function sourcePhrase(kind: string | null, target: string, name: string | null): string {
  switch (kind) {
    case 'url': return `from ${name ?? target}`;
    case 'manual': return 'added by hand';
    case 'paste': return 'from a pasted list';
    case 'geo': return `of ${target}`;
    case 'restore': return 'from a restore';
    case 'preset': return `of ${name ?? target}`;
    case 'unrecorded': return 'whose source was not recorded';
    default: return `from ${target || 'a source'}`;
  }
}

function describeList(e: AuditEntry, verb: string, list: ListWords): AuditDescription | null {
  const target = e.target ?? '';
  const f = fields(e.details);
  switch (verb) {
    case 'add_preset': {
      // One event for a whole preset: target its name, details the domains it added.
      const added = num(f, 'added');
      const already = num(f, 'already') ?? 0;
      if (added === null) return null;
      const domains = Array.isArray(f?.domains) ? (f.domains as unknown[]).filter((x): x is string => typeof x === 'string') : [];
      return {
        event: `Added ${target || 'a preset'} (${count(added, list.imported[0], list.imported[1])}) to ${list.label}`,
        details: join([domains.length ? domains.join(', ') : null, already > 0 ? `${formatCount(already)} already listed` : null]),
        kind: 'change',
      };
    }
    case 'add':
      // The details of an add are the note typed with it, as text.
      return { event: `Added ${target || 'an entry'} to ${list.label}`, details: e.details ? `Note: ${e.details}` : null, kind: 'change' };
    case 'remove':
      return { event: target ? `Removed ${target} from ${list.label}` : `Removed an entry from ${list.label}`, details: null, kind: 'change' };
    case 'bulk_remove': {
      const n = num(f, 'removed');
      return n === null ? null : { event: `Removed ${count(n, list.one, list.many)}`, details: 'A selection removed at once', kind: 'change' };
    }
    case 'clear': {
      const n = num(f, 'removed');
      if (n === null) return null;
      const event = n === 0 ? `Emptied ${list.label}, which held no entry` : n === 1 ? `Removed the only ${list.one}` : `Removed all ${count(n, list.one, list.many)}`;
      return { event, details: null, kind: 'change' };
    }
    case 'import': {
      const added = num(f, 'added');
      if (added === null) return null;
      const [one, many] = list.imported;
      const skipped = num(f, 'skipped') ?? 0;
      const bogon = num(f, 'bogon_skipped') ?? 0;
      const name = str(f, 'name');
      const from = str(f, 'from');
      const event = from === 'paste'
        ? `Added ${count(added, one, many)} to ${list.label} from a pasted list`
        : `Imported ${count(added, one, many)} from ${name ?? (target || 'a URL')}`;
      return {
        event,
        details: join([
          from !== 'paste' && name && target ? `From ${target}` : null,
          skipped > 0 ? `${formatCount(skipped)} skipped (already listed or not valid)` : null,
          bogon > 0 ? `${count(bogon, 'private or LAN range', 'private or LAN ranges')} left out` : null,
        ]),
        kind: 'change',
      };
    }
    case 'remove_source': {
      const n = num(f, 'removed');
      // #426 wrote "source=<id>" and "<n> entries removed" as text.
      if (n === null) return { event: `Removed a source from ${list.label}`, details: join([target, e.details]), kind: 'change' };
      return {
        event: `Removed ${count(n, list.one, list.many)} ${sourcePhrase(str(f, 'kind'), target, str(f, 'name'))}`,
        details: str(f, 'kind') === 'url' && str(f, 'name') && target ? `From ${target}` : null,
        kind: 'change',
      };
    }
    case 'restore': {
      const added = num(f, 'added');
      if (added === null) return null;
      const skipped = num(f, 'skipped') ?? 0;
      return {
        event: `Restored ${count(added, list.one, list.many)} from a backup`,
        details: skipped > 0 ? `${formatCount(skipped)} not valid or over the limit, not restored` : null,
        kind: 'change',
      };
    }
  }
  return null;
}

function describeRefresh(e: AuditEntry): AuditDescription | null {
  const f = fields(e.details);
  const ip = f?.ip_blacklist as Fields | undefined;
  const dom = f?.domain_blacklist as Fields | undefined;
  const ipAdded = num(ip ?? null, 'added');
  const domAdded = num(dom ?? null, 'added');
  if (ipAdded === null || domAdded === null) return null;
  const fetched = (num(ip ?? null, 'fetched') ?? 0) + (num(dom ?? null, 'fetched') ?? 0);
  const failed = (num(ip ?? null, 'failed') ?? 0) + (num(dom ?? null, 'failed') ?? 0);
  const notAdded = num(dom ?? null, 'not_added') ?? 0;
  return {
    event: `Auto-refresh added ${count(ipAdded, 'blocked IP', 'blocked IPs')} and ${count(domAdded, 'blocked domain', 'blocked domains')}`,
    details: join([
      `${formatCount(fetched)} of ${count(fetched + failed, 'list', 'lists')} read${failed > 0 ? `, ${formatCount(failed)} could not be fetched` : ''}`,
      notAdded > 0 ? `${count(notAdded, 'domain', 'domains')} not added: the domain blacklist is at its limit` : null,
    ]),
    kind: 'change',
  };
}

function describeGeo(e: AuditEntry): AuditDescription | null {
  const f = fields(e.details);
  const added = num(f, 'added');
  if (added === null) return null;
  const countries = (e.target ?? '').split(',').filter(Boolean).join(', ');
  const failed = Array.isArray(f?.failed) ? (f.failed as unknown[]).filter((x): x is string => typeof x === 'string') : [];
  return {
    event: `Blocked ${count(added, 'address block', 'address blocks')} of ${countries || 'the requested countries'}`,
    details: failed.length ? `Not imported: ${failed.join('; ')}` : null,
    kind: 'change',
  };
}

/** Schema version 5: egress entries stored as "*.name", which Squid matches against nothing. */
function describeEgressRewrite(e: AuditEntry): AuditDescription | null {
  const f = fields(e.details);
  const rewritten = num(f, 'rewritten');
  const dropped = num(f, 'dropped');
  if (rewritten === null || dropped === null) return null;
  const entries = Array.isArray(f?.entries) ? (f.entries as unknown[]).filter((x): x is string => typeof x === 'string') : [];
  return {
    event: `The upgrade rewrote ${count(rewritten, 'egress entry', 'egress entries')} from *.name to .name`,
    details: join([
      entries.length
        ? entries.join(', ') + (rewritten > entries.length ? `, and ${formatCount(rewritten - entries.length)} more` : '')
        : null,
      dropped > 0 ? `${count(dropped, 'entry', 'entries')} removed: already listed as .name, or a bare *.` : null,
    ]),
    kind: 'change',
  };
}

/** The legacy removal (before the lists were named): target "id=42", details the table. */
function describeLegacyDelete(e: AuditEntry): AuditDescription {
  const list = LISTS[e.details ?? ''] ?? (e.details === 'dst_allowlist' ? LISTS.egress_allowlist : undefined);
  const id = (e.target ?? '').replace(/^id=/, '');
  return {
    event: list ? `Removed entry ${id || 'with no id'} from ${list.label}` : `Removed entry ${id || 'with no id'}`,
    details: 'Recorded before removals named the entry',
    kind: 'change',
  };
}

export function describeAudit(e: AuditEntry): AuditDescription {
  const action = e.action ?? '';
  if (SIGN_INS[action]) return describeSignIn(e, SIGN_INS[action]);
  if (action === 'login_failed') {
    return { event: 'Sign-in failed', details: join([e.target ? `From ${e.target}` : null, e.details]), kind: 'signin-failed' };
  }
  if (PLAIN[action]) return { event: PLAIN[action], details: e.details || null, kind: 'change' };
  if (action === 'update_settings' || action === 'update_setting') {
    const keys = (e.target ?? '').split(',').filter(Boolean);
    // A row with values names each change; an older row only the keys.
    const details = settingChanges(fields(e.details)) ?? (keys.length ? keys.map(settingName).join(', ') : null);
    const event = keys.length === 1 ? `Changed ${settingName(keys[0])}` : keys.length ? `Changed ${count(keys.length, 'setting', 'settings')}` : 'Changed settings';
    return { event, details, kind: 'change' };
  }
  if (action.startsWith('egress_provider_')) {
    const d = describeProvider(e, action);
    if (d) return d;
  }
  if (action === 'delete_ip' || action === 'delete_domain') return describeLegacyDelete(e);
  if (action === 'refresh_blacklists') return describeRefresh(e) ?? verbatim(e);
  if (action === 'geo_block') return describeGeo(e) ?? verbatim(e);
  if (action === 'rewrite_egress_wildcards') return describeEgressRewrite(e) ?? verbatim(e);
  const m = action.match(LIST_ACTION);
  if (m) return describeList(e, m[1], LISTS[m[2]]) ?? verbatim(e);
  return verbatim(e);
}

// A cell that starts with = + - @ (or a tab/CR) is a formula to Excel,
// LibreOffice and Sheets, and these fields are attacker-controlled: a failed
// login stores whatever username was sent, unauthenticated. A leading
// apostrophe makes the spreadsheet show the text as text.
function csvCell(value: unknown): string {
  const raw = String(value ?? '');
  const text = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  return `"${text.replace(/"/g, '""')}"`;
}

/** The rows as CSV: the time in the viewer's zone, the sentence, and what was recorded. */
export function auditCsv(rows: AuditEntry[]): string {
  const lines = [['time', 'timestamp_utc', 'username', 'event', 'details', 'action', 'target', 'recorded_details']];
  for (const e of rows) {
    const d = describeAudit(e);
    lines.push([formatDateTime(e.timestamp), e.timestamp, e.username ?? '', d.event, d.details ?? '', e.action, e.target ?? '', e.details ?? '']);
  }
  return lines.map((r) => r.map(csvCell).join(',')).join('\n');
}
