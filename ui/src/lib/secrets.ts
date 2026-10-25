import type { SettingRow } from '../types';

/**
 * The settings the backend stores encrypted and never returns
 * (crypto.SensitiveKeys in backend-go). Listed here too so a row from an
 * older backend, which still returned the plaintext, is treated the same way.
 */
export const SECRET_KEYS: ReadonlySet<string> = new Set([
  'webhook_url',
  'gotify_url',
  'gotify_token',
  'teams_webhook_url',
  'telegram_bot_token',
  'telegram_chat_id',
  'ntfy_url',
  'ntfy_topic',
]);

/** What the page knows about a secret: never its value. */
export type SecretState = 'set' | 'unset' | 'unreadable';

/** What the operator did to a secret since the last save. */
export type SecretEdit = { kind: 'replace'; value: string } | { kind: 'clear' };

export interface ParsedSettings {
  /** Every setting that is not a secret, by name. */
  values: Record<string, string>;
  /** Every secret the backend reported, by name. */
  secrets: Record<string, SecretState>;
}

export function isSecretRow(row: SettingRow): boolean {
  return row.secret === true || SECRET_KEYS.has(row.setting_name);
}

/** Split the GET /api/settings rows into plain values and secret states. */
export function parseSettings(rows: SettingRow[] | null | undefined): ParsedSettings {
  const values: Record<string, string> = {};
  const secrets: Record<string, SecretState> = {};
  for (const row of rows ?? []) {
    if (isSecretRow(row)) {
      secrets[row.setting_name] = row.decrypt_failed
        ? 'unreadable'
        : row.is_set || row.setting_value
          ? 'set'
          : 'unset';
    } else {
      values[row.setting_name] = row.setting_value;
    }
  }
  return { values, secrets };
}

export function secretStateOf(secrets: Record<string, SecretState>, key: string): SecretState {
  return secrets[key] ?? 'unset';
}

/**
 * The part of a save request that concerns secrets: a value the operator
 * typed goes in the body, a secret the operator removed goes in clear, and
 * a secret nobody touched is not sent at all, so an unreadable one cannot
 * be overwritten by the empty value the page holds for it.
 */
export function secretPayload(edits: Record<string, SecretEdit | undefined>): { body: Record<string, string>; clear: string[] } {
  const body: Record<string, string> = {};
  const clear: string[] = [];
  for (const [key, edit] of Object.entries(edits)) {
    if (!edit) continue;
    if (edit.kind === 'clear') clear.push(key);
    else if (edit.value !== '') body[key] = edit.value;
  }
  clear.sort();
  return { body, clear };
}
