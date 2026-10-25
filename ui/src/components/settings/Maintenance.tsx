import { useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../ui/card';
import { Database, Download, Trash2, RotateCcw, Wrench, Upload, FileJson } from 'lucide-react';
import toast from 'react-hot-toast';
import { api, getErrorMessage } from '../../lib/api';
import { useConfirm } from '../../hooks/useConfirm';
import { applyToProxy, describeApply, type ApplyOutcome } from '../../lib/reload';
import { backupFileName, downloadJson, parseBackupFile, type BackupSummary, type RestoreResponse } from '../../lib/backup';
import { formatCount, formatDateTime } from '../../lib/format';
import { cn } from '../../lib/utils';

function Btn({ icon: Icon, label, sub, onClick, destructive, disabled }: {
  icon: typeof Download; label: string; sub: string; onClick: () => void; destructive?: boolean; disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`flex items-center gap-3 p-3 border border-border rounded-lg bg-background/50 transition-colors text-left w-full disabled:opacity-50 ${
        destructive ? 'hover:bg-destructive/10 group' : 'hover:bg-secondary/50'
      }`}
    >
      <Icon aria-hidden="true" className={`w-4 h-4 shrink-0 ${destructive ? 'text-destructive group-hover:text-red-400' : 'text-primary'}`} />
      <div>
        <span className={`text-xs font-medium ${destructive ? 'text-destructive group-hover:text-red-400' : ''}`}>{label}</span>
        <p className="text-[10px] text-muted-foreground">{sub}</p>
      </div>
    </button>
  );
}

/** What the restore dialog says the file will change. */
function RestoreSummaryText({ summary }: { summary: BackupSummary }) {
  const lists = summary.lists.filter((l) => l.count > 0);
  return (
    <div className="space-y-2">
      {summary.settings > 0 && (
        <p>The {formatCount(summary.settings)} settings in the file replace the current values.</p>
      )}
      {lists.length > 0 && (
        <div>
          <p>These list entries are added:</p>
          <ul className="mt-1 list-disc pl-4">
            {lists.map((l) => <li key={l.name}>{l.label}: {formatCount(l.count)}</li>)}
          </ul>
        </div>
      )}
      <p>Nothing is removed: settings and entries that are not in the file stay as they are.</p>
      <p>
        {summary.exportedAt ? `Exported ${formatDateTime(summary.exportedAt)}` : 'The file does not say when it was exported'}
        {summary.appVersion ? ` by version ${summary.appVersion}.` : '.'}
        {' '}Alert channel secrets in it are encrypted with the key of the install that made it; on another install they cannot be read and must be entered again.
      </p>
    </div>
  );
}

type RestoreOutcome =
  | { kind: 'invalid'; message: string }
  | { kind: 'failed'; message: string }
  | { kind: 'done'; response: RestoreResponse; apply: ApplyOutcome };

const TONE = {
  success: 'border-emerald-500/30 bg-emerald-500/5',
  warning: 'border-amber-500/30 bg-amber-500/5',
  danger: 'border-destructive/40 bg-destructive/5',
};

function RestoreResult({ outcome }: { outcome: RestoreOutcome }) {
  if (outcome.kind !== 'done') {
    return (
      <div role="status" className={cn('mt-3 rounded-lg border p-3 text-xs', TONE.danger)}>
        <p className="font-medium">{outcome.kind === 'invalid' ? 'The file was not restored' : 'The restore failed'}</p>
        <p className="mt-1">{outcome.message}</p>
      </div>
    );
  }
  const r = outcome.response;
  const apply = describeApply(outcome.apply, 'Restored');
  const skipped = r.skipped_settings ?? [];
  const failed = r.failed_files ?? [];
  const restoredSettings = r.restored_settings;
  const restoredEntries = r.restored_entries;
  return (
    <div role="status" className={cn('mt-3 space-y-1.5 rounded-lg border p-3 text-xs', TONE[failed.length ? 'warning' : apply.tone])}>
      <p className="font-medium">
        {restoredSettings !== undefined && restoredEntries !== undefined
          ? `Restored ${formatCount(restoredSettings)} settings and ${formatCount(restoredEntries)} list entries.`
          : `Restored ${formatCount(r.restored ?? 0)} items.`}
      </p>
      {skipped.length > 0 && (
        <div>
          <p>Not restored:</p>
          <ul className="mt-0.5 list-disc pl-4">
            {skipped.map((s) => <li key={s.key}><code className="font-mono">{s.key}</code>: {s.reason}</li>)}
          </ul>
        </div>
      )}
      {!r.skipped_settings && (r.skipped ?? 0) > 0 && <p>{formatCount(r.skipped ?? 0)} settings were not restored; this backend does not say which.</p>}
      {(r.skipped_entries ?? 0) > 0 && <p>{formatCount(r.skipped_entries ?? 0)} list entries failed validation and were skipped.</p>}
      {failed.length > 0 && <p>These proxy configuration files could not be written: {failed.join(', ')}.</p>}
      <p>{apply.text}</p>
    </div>
  );
}

export function Maintenance() {
  const { confirm, dialog } = useConfirm();
  const fileRef = useRef<HTMLInputElement>(null);
  const [restoring, setRestoring] = useState(false);
  const [restoreOutcome, setRestoreOutcome] = useState<RestoreOutcome | null>(null);

  const action = async (label: string, fn: () => Promise<unknown>) => {
    const id = toast.loading(`${label}...`);
    try {
      await fn();
      toast.success(`${label} complete`, { id });
    } catch {
      toast.error(`${label} failed`, { id });
    }
  };

  // The restorable backup: settings and the five lists, read back by Restore.
  const handleBackup = () => action('Backup', async () => {
    const res = await api.get('maintenance/backup-config');
    const envelope = res.data?.data;
    if (!envelope?.settings) throw new Error('the backup has no settings');
    downloadJson(envelope, backupFileName());
  });

  // The full database dump, for analysis. Restore cannot read it.
  const handleExport = () => action('Database export', async () => {
    const res = await api.get('database/export', { responseType: 'blob' });
    const url = window.URL.createObjectURL(new Blob([res.data]));
    const a = document.createElement('a'); a.href = url;
    a.download = `proxy-database-export-${new Date().toISOString().slice(0, 10)}.json`;
    a.click(); window.URL.revokeObjectURL(url);
  });

  const handleRestoreFile = async (file: File) => {
    let parsed: ReturnType<typeof parseBackupFile>;
    try {
      parsed = parseBackupFile(await file.text());
    } catch (err) {
      setRestoreOutcome({ kind: 'invalid', message: err instanceof Error ? err.message : 'The file cannot be read.' });
      return;
    }
    const ok = await confirm({
      title: `Restore ${file.name}?`,
      body: <RestoreSummaryText summary={parsed.summary} />,
      confirmLabel: 'Restore',
      destructive: true,
    });
    if (!ok) return;
    setRestoring(true);
    setRestoreOutcome(null);
    try {
      const res = await api.post('maintenance/restore-config', parsed.envelope);
      const apply = await applyToProxy();
      setRestoreOutcome({ kind: 'done', response: res.data ?? {}, apply });
    } catch (err) {
      setRestoreOutcome({ kind: 'failed', message: getErrorMessage(err, 'The backend did not accept the file.') });
    } finally {
      setRestoring(false);
    }
  };

  const handleClearCache = async () => {
    if (!(await confirm({
      title: 'Clear proxy cache?',
      body: 'Frees proxy memory now; cached objects are re-fetched on the next request.',
      confirmLabel: 'Clear cache',
      destructive: true,
    }))) return;
    action('Clear cache', () => api.post('maintenance/clear-cache'));
  };
  const handleOptimize = () => action('Optimize DB', () => api.post('database/optimize'));
  const handleResetCounters = async () => {
    if (!(await confirm({
      title: 'Reset all counters?',
      body: 'Permanently clears all proxy logs and WAF statistics. This cannot be undone.',
      confirmLabel: 'Reset counters',
      destructive: true,
    }))) return;
    action('Reset counters', () => api.post('counters/reset'));
  };
  const handleReloadConfig = () => action('Reload config', () => api.post('maintenance/reload-config'));
  const handleReloadDns = () => action('Reload DNS', () => api.post('maintenance/reload-dns'));

  return (
    <Card>
      {dialog}
      <CardHeader className="p-4 pb-2">
        <div className="flex items-center gap-2">
          <Database aria-hidden="true" className="w-4 h-4 text-muted-foreground" />
          <CardTitle className="text-sm">Maintenance</CardTitle>
        </div>
        <CardDescription className="text-xs">System backup, cache, and database management</CardDescription>
      </CardHeader>
      <CardContent className="p-4 pt-0">
        <div className="grid grid-cols-2 gap-2">
          <Btn icon={Download} label="Backup Config" sub="Settings and lists, restorable" onClick={handleBackup} />
          <Btn icon={Upload} label={restoring ? 'Restoring...' : 'Restore Config'} sub="From a backup file" onClick={() => fileRef.current?.click()} disabled={restoring} />
          <Btn icon={Wrench} label="Optimize DB" sub="Vacuum + reindex" onClick={handleOptimize} />
          <Btn icon={FileJson} label="Database export" sub="Every table, not restorable" onClick={handleExport} />
          <Btn icon={RotateCcw} label="Reload Config" sub="Apply Squid changes" onClick={handleReloadConfig} />
          <Btn icon={RotateCcw} label="Reload DNS" sub="Apply domain blocklist" onClick={handleReloadDns} />
          <Btn icon={RotateCcw} label="Reset Counters" sub="Zero all stats" onClick={handleResetCounters} destructive />
          <Btn icon={Trash2} label="Clear Cache" sub="Free proxy memory" onClick={handleClearCache} destructive />
        </div>
        <input
          ref={fileRef}
          type="file"
          accept="application/json,.json"
          aria-label="Backup file to restore"
          className="sr-only"
          tabIndex={-1}
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = '';
            if (file) void handleRestoreFile(file);
          }}
        />
        {restoreOutcome && <RestoreResult outcome={restoreOutcome} />}
      </CardContent>
    </Card>
  );
}
