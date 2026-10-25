/**
 * What one section's Save sends and what it changes in the cached GET.
 */
import type { SettingRow } from '../types';
import { formatClock } from './format';
import { describeApply, type ApplyOutcome } from './reload';
import { secretPayload, type SecretEdit } from './secrets';
import { APPLY_HELP, APPLY_MODE, SECTION_KEYS, isSecretKey, type ApplyMode, type SectionId } from './settingsMeta';

export interface SectionRequest {
  /** The keys in the body that are not secrets. */
  sent: string[];
  body: Record<string, string>;
  /** Secrets to remove (?clear=). */
  clear: string[];
  /** The keys whose value changes, secrets included. */
  changed: string[];
  /** How the changed keys take effect. */
  modes: ApplyMode[];
}

/**
 * The request for a section: every key of the section that has a value,
 * stored or typed (so a toggle travels with its parameters), the secrets
 * the operator typed, and the ones removed. A key the backend has no value
 * for and nobody typed is not sent, and nothing outside the section is.
 */
export function sectionRequest(
  id: SectionId,
  stored: Record<string, string>,
  edits: Record<string, string>,
  secretEdits: Record<string, SecretEdit>,
): SectionRequest {
  const keys = SECTION_KEYS[id].filter((k) => !isSecretKey(k));
  const sent = keys.filter((k) => k in edits || k in stored);
  const body: Record<string, string> = {};
  for (const k of sent) body[k] = k in edits ? edits[k] : stored[k];
  const ownSecrets = Object.fromEntries(Object.entries(secretEdits).filter(([k]) => SECTION_KEYS[id].includes(k)));
  const secret = secretPayload(ownSecrets);
  Object.assign(body, secret.body);
  const changed = [...Object.keys(edits).filter((k) => keys.includes(k)), ...Object.keys(ownSecrets)];
  const modes = [...new Set(changed.map((k) => APPLY_MODE[k]).filter((m): m is ApplyMode => !!m))];
  return { sent, body, clear: secret.clear, changed, modes };
}

/** The GET rows as they are after a save the backend accepted. */
export function rowsAfterSave(rows: SettingRow[] | null | undefined, req: Pick<SectionRequest, 'body' | 'clear'>): SettingRow[] {
  const next = (rows ?? []).map((r) => ({ ...r }));
  const byName = new Map(next.map((r) => [r.setting_name, r]));
  for (const [key, value] of Object.entries(req.body)) {
    const row = byName.get(key);
    if (isSecretKey(key)) {
      const secretRow = { setting_name: key, setting_value: '', secret: true, is_set: true, decrypt_failed: false };
      if (row) Object.assign(row, secretRow);
      else next.push(secretRow);
    } else if (row) {
      row.setting_value = value;
    } else {
      next.push({ setting_name: key, setting_value: value });
    }
  }
  for (const key of req.clear) {
    const row = byName.get(key);
    if (row) Object.assign(row, { is_set: false, decrypt_failed: false });
  }
  return next;
}

/** The outcome of a section's last Save, as the page reports it. */
export type SaveResult =
  | { kind: 'saved'; at: Date; modes: ApplyMode[]; apply?: ApplyOutcome; failedFiles: string[] }
  | { kind: 'invalid'; fields: string[]; outside?: string }
  | { kind: 'error'; message: string };

type Tone = 'success' | 'warning' | 'danger';

const ORDER: ApplyMode[] = ['dns', 'waf', 'live', 'daily', 'cycle'];

/** The lines a finished save shows, most important first. */
export function describeSave(result: SaveResult): { tone: Tone; lines: string[]; retry: boolean } {
  if (result.kind === 'error') return { tone: 'danger', lines: [`Not saved: ${result.message}`], retry: false };
  if (result.kind === 'invalid') {
    const n = result.fields.length;
    const lines = n ? [`Not saved: ${n === 1 ? '1 field needs' : `${n} fields need`} attention.`] : [];
    if (result.outside) lines.push(`Not saved: ${result.outside}`);
    return { tone: 'danger', lines, retry: false };
  }
  const lines: string[] = [];
  let tone: Tone = 'success';
  let retry = false;
  if (result.apply) {
    const a = describeApply(result.apply);
    lines.push(a.text);
    tone = a.tone;
    retry = result.apply.kind !== 'applied';
  } else {
    lines.push(`Saved at ${formatClock(result.at)}.`);
  }
  for (const mode of ORDER) if (result.modes.includes(mode)) lines.push(APPLY_HELP[mode]);
  if (result.failedFiles.length) {
    tone = tone === 'danger' ? 'danger' : 'warning';
    lines.push(`These proxy configuration files could not be written, so the proxy still uses the previous ones: ${result.failedFiles.join(', ')}.`);
  }
  return { tone, lines, retry };
}

