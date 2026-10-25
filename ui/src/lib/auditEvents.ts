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
  ip_whitelist: { label: 'Allowed IPs', one: 'allowed IP', many: 'allowed IPs', imported: ['IP', 'IPs'] },
  domain_whitelist: { label: 'Allowed domains', one: 'allowed domain', many: 'allowed domains', imported: ['domain', 'domains'] },
  egress_allowlist: { label: 'the egress allowlist', one: 'egress destination', many: 'egress destinations', imported: ['destination', 'destinations'] },
};

const LIST_NAMES = Object.keys(LISTS).join('|');
const LIST_ACTION = new RegExp(`^(add|remove|bulk_remove|clear|import|remove_source|restore)_(${LIST_NAMES})$`);

const SIGN_INS: Record<string, AuditDescription> = {
  login: { event: 'Signed in', details: null, kind: 'signin' },
  logout: { event: 'Signed out', details: null, kind: 'signin' },
};

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

/** The row as recorded, for a key or a shape this module does not know. */
function verbatim(e: AuditEntry): AuditDescription {
  return { event: e.action || 'No action recorded', details: join([e.target, e.details]), kind: 'change' };
}

/** Where a removed source's entries came from, as the end of a sentence. */
function sourcePhrase(kind: string | null, target: string, name: string | null): string {
  switch (kind) {
    case 'url': return `from ${name ?? target}`;
    case 'manual': return 'added by hand';
    case 'paste': return 'from a pasted list';
    case 'geo': return `of ${target}`;
    case 'restore': return 'from a restore';
    case 'unrecorded': return 'whose source was not recorded';
    default: return `from ${target || 'a source'}`;
  }
}

function describeList(e: AuditEntry, verb: string, list: ListWords): AuditDescription | null {
  const target = e.target ?? '';
  const f = fields(e.details);
  switch (verb) {
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
  if (SIGN_INS[action]) return SIGN_INS[action];
  if (action === 'login_failed') {
    return { event: 'Sign-in failed', details: join([e.target ? `From ${e.target}` : null, e.details]), kind: 'signin-failed' };
  }
  if (PLAIN[action]) return { event: PLAIN[action], details: e.details || null, kind: 'change' };
  if (action === 'update_settings') {
    const keys = (e.target ?? '').split(',').filter(Boolean);
    return { event: keys.length ? `Changed ${count(keys.length, 'setting', 'settings')}` : 'Changed settings', details: keys.length ? keys.join(', ') : null, kind: 'change' };
  }
  if (action === 'update_setting') return { event: `Changed the setting ${e.target || 'with no name'}`, details: e.details || null, kind: 'change' };
  if (action === 'delete_ip' || action === 'delete_domain') return describeLegacyDelete(e);
  if (action === 'refresh_blacklists') return describeRefresh(e) ?? verbatim(e);
  if (action === 'geo_block') return describeGeo(e) ?? verbatim(e);
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
