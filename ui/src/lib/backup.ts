/**
 * The restorable backup: GET /api/maintenance/backup-config answers
 * { status, data: envelope } and POST /api/maintenance/restore-config takes
 * the envelope back (docs/api/settings.md). The file the page saves is the
 * envelope itself.
 */

export const LIST_LABELS: Record<string, string> = {
  ip_blacklist: 'IP blacklist',
  ip_whitelist: 'IP whitelist',
  domain_blacklist: 'Domain blacklist',
  domain_whitelist: 'Domain whitelist',
  dst_allowlist: 'Egress allowlist',
};

export interface BackupEnvelope {
  backup_version?: number;
  app_version?: string;
  exported_at?: string;
  settings?: Record<string, string>;
  /** The version 1 shape: a bare settings map. */
  config?: Record<string, string>;
  lists?: Record<string, { value: string; description?: string }[]>;
  egress_providers?: { kind?: string; name: string; url?: string; enabled?: boolean }[];
}

export interface BackupSummary {
  settings: number;
  lists: { name: string; label: string; count: number }[];
  egressProviders: number;
  exportedAt?: string;
  appVersion?: string;
}

const isMap = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Read a backup file. Throws an Error whose message says what is wrong, for
 * a file that is not JSON, a database export (not restorable) or a file with
 * nothing to restore.
 */
export function parseBackupFile(text: string): { envelope: BackupEnvelope; summary: BackupSummary } {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error('The file is not JSON.');
  }
  // A file saved from the raw API answer still carries the { status, data } wrapper.
  if (isMap(raw) && isMap(raw.data) && !('settings' in raw) && !('config' in raw)) raw = raw.data;
  if (!isMap(raw)) throw new Error('The file is not a backup made by Download a backup.');
  if (Array.isArray(raw.settings)) {
    throw new Error('This is a database export, which cannot be restored. Use a file made by Download a backup.');
  }
  const settings = isMap(raw.settings) ? raw.settings : isMap(raw.config) ? raw.config : undefined;
  const lists = isMap(raw.lists) ? raw.lists : undefined;
  const settingsCount = settings ? Object.keys(settings).length : 0;
  const listSummary = Object.entries(lists ?? {})
    .filter(([, entries]) => Array.isArray(entries))
    .map(([name, entries]) => ({ name, label: LIST_LABELS[name] ?? name, count: (entries as unknown[]).length }));
  const egressProviders = Array.isArray(raw.egress_providers) ? raw.egress_providers.length : 0;
  if (settingsCount === 0 && listSummary.every((l) => l.count === 0) && egressProviders === 0) {
    throw new Error('The file holds no settings and no list entries to restore.');
  }
  return {
    envelope: raw as BackupEnvelope,
    summary: {
      settings: settingsCount,
      lists: listSummary,
      egressProviders,
      exportedAt: typeof raw.exported_at === 'string' ? raw.exported_at : undefined,
      appVersion: typeof raw.app_version === 'string' ? raw.app_version : undefined,
    },
  };
}

/** What POST /api/maintenance/restore-config answered. */
export interface RestoreResponse {
  restored_settings?: number;
  restored_entries?: number;
  restored_egress_providers?: number;
  egress_providers_refreshing?: boolean;
  skipped_settings?: { key: string; reason: string }[];
  skipped_entries?: number;
  failed_files?: string[];
  /** Older backends: totals only. */
  restored?: number;
  skipped?: number;
}

export function backupFileName(now = new Date()): string {
  return `proxy-backup-${now.toISOString().slice(0, 10)}.json`;
}

/** Offer a JSON value to the browser as a file download. */
export function downloadJson(value: unknown, fileName: string): void {
  const url = window.URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}
