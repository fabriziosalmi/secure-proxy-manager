/**
 * Backup, restore and the maintenance actions of Admin and backup. Each
 * action reports its own result under its button, from what the endpoint
 * answered, and says what it cannot confirm. The destructive ones ask first.
 *
 * Backup is the restorable pair (GET maintenance/backup-config, POST
 * maintenance/restore-config). The database export is every table, for
 * analysis, and Restore refuses it.
 *
 * Clear the cache: the proxy's watchdog stops Squid, deletes everything in
 * its cache_dir, recreates it with "squid -z" and starts Squid again, which
 * also empties the memory cache (proxy/blacklist_watchdog.py). The endpoint
 * waits up to 45 seconds for the watchdog's answer: success with the objects
 * removed, pending when nothing answered, 500 with the step that stopped it.
 */
import { useRef, useState, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Upload } from 'lucide-react';
import { api, getErrorMessage } from '../../lib/api';
import { useConfirm } from '../../hooks/useConfirm';
import { applyToProxy, describeApply, type ApplyOutcome } from '../../lib/reload';
import { backupFileName, downloadJson, parseBackupFile, type BackupSummary, type RestoreResponse } from '../../lib/backup';
import { formatClock, formatCount, formatDateTime, formatKilobytes } from '../../lib/format';
import { describeListResend, RESEND_UNCONFIRMED } from '../../lib/listResend';
import { cn } from '../../lib/utils';
import { Section } from '../ui/Section';
import { Button } from '../ui/Button';

type Tone = 'success' | 'warning' | 'danger';
const TONE: Record<Tone, string> = { success: 'text-success', warning: 'text-warning-ink', danger: 'text-danger' };

/** What the restore dialog says the file will change. */
function RestoreSummaryText({ summary }: { summary: BackupSummary }) {
  const lists = summary.lists.filter((l) => l.count > 0);
  const listEntries = lists.reduce((acc, l) => acc + l.count, 0);
  const providers = summary.egressProviders ?? 0;
  const addedLead = providers > 0
    ? `These ${formatCount(listEntries)} list ${listEntries === 1 ? 'entry' : 'entries'} and ${formatCount(providers)} egress ${providers === 1 ? 'provider' : 'providers'} are added:`
    : 'These list entries are added:';
  return (
    <div className="space-y-2">
      {summary.settings > 0 && (
        <p>The {formatCount(summary.settings)} settings in the file replace the current values.</p>
      )}
      {(lists.length > 0 || providers > 0) && (
        <div>
          <p>{addedLead}</p>
          <ul className="mt-1 list-disc pl-4">
            {lists.map((l) => <li key={l.name}>{l.label}: {formatCount(l.count)}</li>)}
            {providers > 0 && <li>Egress providers: {formatCount(providers)}</li>}
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

function RestoreResult({ outcome }: { outcome: RestoreOutcome }) {
  if (outcome.kind !== 'done') {
    return (
      <div className={cn('flex flex-col gap-1 text-sm', TONE.danger)}>
        <p className="font-medium">{outcome.kind === 'invalid' ? 'The file was not restored' : 'The restore failed'}</p>
        <p>{outcome.message}</p>
      </div>
    );
  }
  const r = outcome.response;
  const apply = describeApply(outcome.apply, 'Restored');
  const skipped = r.skipped_settings ?? [];
  const failed = r.failed_files ?? [];
  const providersRestored = r.restored_egress_providers ?? 0;
  return (
    <div className={cn('flex flex-col gap-1.5 text-sm', TONE[failed.length ? 'warning' : apply.tone])}>
      <p className="font-medium">
        {r.restored_settings !== undefined && r.restored_entries !== undefined
          ? providersRestored > 0
            ? `Restored ${formatCount(r.restored_settings)} settings, ${formatCount(r.restored_entries)} list entries, and ${formatCount(providersRestored)} egress ${providersRestored === 1 ? 'provider' : 'providers'}.`
            : `Restored ${formatCount(r.restored_settings)} settings and ${formatCount(r.restored_entries)} list entries.`
          : `Restored ${formatCount(r.restored ?? 0)} items.`}
      </p>
      {r.egress_providers_refreshing && <p>The egress provider lists are downloading in the background.</p>}
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

/** One line of result under an action: what the endpoint answered. */
type Outcome = { tone: Tone; text: string } | null;

function ActionRow({ title, help, button, outcome, busy, onRun, danger }: {
  title: string; help: ReactNode; button: string; outcome: Outcome; busy: boolean; onRun: () => void; danger?: boolean;
}) {
  return (
    <li className="flex flex-col gap-2 border-t border-line-subtle py-4 first:border-t-0 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 flex-[1_1_280px] flex-col gap-0.5">
          <h4 className="text-sm font-semibold text-ink">{title}</h4>
          <p className="text-sm leading-5 text-ink-muted">{help}</p>
        </div>
        <Button variant={danger ? 'danger-outline' : 'secondary'} onClick={onRun} disabled={busy}>
          {busy ? 'Working...' : button}
        </Button>
      </div>
      <p role="status" className={cn('text-sm', outcome ? TONE[outcome.tone] : '')}>{outcome?.text}</p>
    </li>
  );
}

export function BackupRestore() {
  const queryClient = useQueryClient();
  const { confirm, dialog } = useConfirm();
  const fileRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState<'backup' | 'restore' | 'export' | null>(null);
  const [backup, setBackup] = useState<Outcome>(null);
  const [exported, setExported] = useState<Outcome>(null);
  const [restoreOutcome, setRestoreOutcome] = useState<RestoreOutcome | null>(null);

  const handleBackup = async () => {
    setBusy('backup');
    try {
      const res = await api.get('maintenance/backup-config');
      const envelope = res.data?.data;
      if (!envelope?.settings) throw new Error('the backup has no settings');
      const name = backupFileName();
      downloadJson(envelope, name);
      setBackup({ tone: 'success', text: `Downloaded ${name} at ${formatClock(new Date())}.` });
    } catch (err) {
      setBackup({ tone: 'danger', text: `No backup was made: ${err instanceof Error && !('response' in err) ? err.message : getErrorMessage(err, 'the backend did not answer')}.` });
    } finally {
      setBusy(null);
    }
  };

  const handleExport = async () => {
    setBusy('export');
    try {
      const res = await api.get('database/export', { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const name = `proxy-database-export-${new Date().toISOString().slice(0, 10)}.json`;
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.click();
      window.URL.revokeObjectURL(url);
      setExported({ tone: 'success', text: `Downloaded ${name}.` });
    } catch (err) {
      setExported({ tone: 'danger', text: `The export failed: ${getErrorMessage(err, 'the backend did not answer')}.` });
    } finally {
      setBusy(null);
    }
  };

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
    setBusy('restore');
    setRestoreOutcome(null);
    try {
      const res = await api.post('maintenance/restore-config', parsed.envelope);
      const apply = await applyToProxy();
      void queryClient.invalidateQueries();
      setRestoreOutcome({ kind: 'done', response: res.data ?? {}, apply });
    } catch (err) {
      setRestoreOutcome({ kind: 'failed', message: getErrorMessage(err, 'The backend did not accept the file.') });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Section level={3} title="Backup and restore">
      {dialog}
      <ul className="flex flex-col">
        <ActionRow
          title="Backup"
          help="The settings, the five lists (blocked and allowed IPs and domains, the egress allowlist), and the list of enabled egress providers and custom URLs (not their downloaded entries), in a file Restore reads back. Alert channel secrets stay encrypted in it."
          button="Download a backup"
          outcome={backup}
          busy={busy === 'backup'}
          onRun={() => void handleBackup()}
        />
        <li className="flex flex-col gap-2 border-t border-line-subtle py-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex min-w-0 flex-[1_1_280px] flex-col gap-0.5">
              <h4 className="text-sm font-semibold text-ink">Restore</h4>
              <p className="text-sm leading-5 text-ink-muted">Adds what a backup file holds, after listing it. Nothing that is not in the file is removed. The proxy reloads afterwards.</p>
            </div>
            <Button icon={<Upload />} onClick={() => fileRef.current?.click()} disabled={busy === 'restore'}>
              {busy === 'restore' ? 'Restoring...' : 'Restore from a file'}
            </Button>
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
          <div role="status">{restoreOutcome && <RestoreResult outcome={restoreOutcome} />}</div>
        </li>
        <ActionRow
          title="Database export"
          help="Every table, the request log and the audit log included, for analysis. It holds the full, unmasked client addresses even when client IP masking is on. Restore cannot read it."
          button="Export the database"
          outcome={exported}
          busy={busy === 'export'}
          onRun={() => void handleExport()}
        />
      </ul>
    </Section>
  );
}

type ActionId = 'reload' | 'dns' | 'cache' | 'reset' | 'optimize';

const sizeOf = async (): Promise<number | null> => {
  try {
    const res = await api.get('database/size');
    const n = res.data?.data?.size_bytes;
    return typeof n === 'number' ? n : null;
  } catch {
    return null;
  }
};

export function MaintenanceActions() {
  const { confirm, dialog } = useConfirm();
  const [busy, setBusy] = useState<ActionId | null>(null);
  const [out, setOut] = useState<Partial<Record<ActionId, Outcome>>>({});

  const run = async (id: ActionId, fn: () => Promise<Outcome>) => {
    setBusy(id);
    setOut((o) => ({ ...o, [id]: null }));
    try {
      const result = await fn();
      setOut((o) => ({ ...o, [id]: result }));
    } catch (err) {
      setOut((o) => ({ ...o, [id]: { tone: 'danger', text: `It failed: ${getErrorMessage(err, 'the backend did not answer')}.` } }));
    } finally {
      setBusy(null);
    }
  };

  const reload = () => run('reload', async () => {
    const a = describeApply(await applyToProxy(), 'Requested');
    return { tone: a.tone, text: a.text };
  });

  const reloadDns = () => run('dns', async () => {
    const res = await api.post('maintenance/reload-dns');
    return { tone: 'success', text: `${describeListResend(res.data?.data)} ${RESEND_UNCONFIRMED}` };
  });

  const clearCache = async () => {
    if (!(await confirm({
      title: 'Empty the proxy cache?',
      body: 'Stops the proxy, deletes every object in its disk cache and starts it again, which also empties its memory cache. Requests in progress are cut off, and new ones are refused until it is back, a few seconds. Each object is then fetched again from its origin.',
      confirmLabel: 'Empty the cache',
      destructive: true,
    }))) return;
    void run('cache', async () => {
      const res = await api.post('maintenance/clear-cache');
      if (res.data?.status === 'pending') {
        return { tone: 'warning', text: 'The proxy did not confirm within 45 seconds: check that the proxy container is running.' };
      }
      const removed: unknown = res.data?.data?.objects_removed;
      const what = typeof removed === 'number' ? `${formatCount(removed)} ${removed === 1 ? 'object' : 'objects'} removed from disk` : 'the disk cache was emptied';
      return { tone: 'success', text: `Emptied at ${formatClock(new Date())}: ${what}, and the proxy is running again.` };
    });
  };

  const resetStats = async () => {
    if (!(await confirm({
      title: 'Delete every logged request?',
      body: 'Every request in the log is deleted, so the Logs, Clients and Overview figures start from zero, and the WAF resets its counters. The audit log is kept. This cannot be undone.',
      confirmLabel: 'Delete and reset',
      destructive: true,
    }))) return;
    void run('reset', async () => {
      const res = await api.post('counters/reset');
      const d = res.data?.data ?? {};
      const logs = typeof d.logs_cleared === 'number' ? `Deleted ${formatCount(d.logs_cleared)} logged ${d.logs_cleared === 1 ? 'request' : 'requests'}.` : 'The log was cleared.';
      const waf = d.waf_reset === true ? 'The WAF reset its counters.' : 'The WAF did not reset its counters: it did not answer, or refused the backend.';
      return { tone: d.waf_reset === true ? 'success' : 'warning', text: `${logs} ${waf}` };
    });
  };

  const optimize = () => run('optimize', async () => {
    const before = await sizeOf();
    await api.post('database/optimize');
    const after = await sizeOf();
    const size = before !== null && after !== null
      ? ` Size ${formatKilobytes(before / 1024)} before, ${formatKilobytes(after / 1024)} after.`
      : ' The size could not be read.';
    return { tone: 'success', text: `Optimized (VACUUM and REINDEX).${size}` };
  });

  return (
    <Section level={3} title="Maintenance">
      {dialog}
      <ul className="flex flex-col">
        <ActionRow title="Reload the proxy" help="Regenerates the proxy configuration from the stored settings and lists, and reports whether the proxy took it. Saving a section already does this." button="Reload the proxy" outcome={out.reload ?? null} busy={busy === 'reload'} onRun={() => void reload()} />
        <ActionRow title="Send the lists again" help="Sends every list to the DNS sinkhole and the proxy again. Use it when a change has not taken effect." button="Send the lists again" outcome={out.dns ?? null} busy={busy === 'dns'} onRun={() => void reloadDns()} />
        <ActionRow title="Empty the cache" help="Stops the proxy, deletes its disk cache and starts it again, which also empties the memory cache. Clients lose their connections for a few seconds." button="Empty disk and memory cache" outcome={out.cache ?? null} busy={busy === 'cache'} onRun={() => void clearCache()} danger />
        <ActionRow title="Reset statistics" help="Deletes every logged request and resets the WAF's counters." button="Reset statistics" outcome={out.reset ?? null} busy={busy === 'reset'} onRun={() => void resetStats()} danger />
        <ActionRow title="Optimize the database" help="Compacts the database file and rebuilds its indexes. The backend waits for it, which can take a while on a large log." button="Optimize" outcome={out.optimize ?? null} busy={busy === 'optimize'} onRun={() => void optimize()} />
      </ul>
    </Section>
  );
}

export function Maintenance() {
  return (
    <>
      <BackupRestore />
      <MaintenanceActions />
    </>
  );
}

