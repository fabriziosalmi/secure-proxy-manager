/**
 * Configuration history (GET /api/config/snapshots): a snapshot of the
 * settings, client groups, WAF policy and egress allowlist is taken before
 * every change to them and on demand. Each one can be compared with the
 * configuration in force (.../diff) and restored (.../restore), which takes a
 * snapshot first, so a restore can be undone by restoring that one. The
 * blacklists and whitelists are not in a snapshot: the full backup has them.
 */
import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, getErrorMessage } from '../../lib/api';
import { formatWhen } from '../../lib/format';
import { diffLines, type Snapshot, type SnapshotDiff } from '../../lib/snapshots';
import { applyToProxy, describeApply } from '../../lib/reload';
import { useConfirm } from '../../hooks/useConfirm';
import { Section } from '../ui/Section';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import { cn } from '../../lib/utils';

const SNAPSHOTS_KEY = ['config', 'snapshots'] as const;

function when(at: number): string {
  return formatWhen(new Date(at * 1000).toISOString(), { style: 'glance' });
}

type Result = { tone: 'success' | 'warning' | 'danger'; text: string } | null;
const TONE = { success: 'text-success', warning: 'text-warning-ink', danger: 'text-danger' } as const;

export function ConfigHistory() {
  const queryClient = useQueryClient();
  const { confirm, dialog } = useConfirm();
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<Result>(null);
  const [compared, setCompared] = useState<{ id: number; lines: string[] } | null>(null);
  const q = useQuery<Snapshot[]>({
    queryKey: SNAPSHOTS_KEY,
    queryFn: async () => (await api.get('config/snapshots')).data?.data ?? [],
  });

  const take = async () => {
    setBusy('take');
    try {
      const res = await api.post('config/snapshots', note.trim() ? { note: note.trim() } : {});
      const created = res.data?.data?.created;
      setResult({ tone: 'success', text: created ? 'Snapshot taken.' : 'The newest snapshot already holds this configuration: none was added.' });
      setNote('');
      void queryClient.invalidateQueries({ queryKey: SNAPSHOTS_KEY });
    } catch (err) {
      setResult({ tone: 'danger', text: `No snapshot was taken: ${getErrorMessage(err, 'the backend did not answer')}.` });
    } finally {
      setBusy(null);
    }
  };

  const diffOf = async (id: number): Promise<SnapshotDiff> => (await api.get(`config/snapshots/${id}/diff`)).data?.data;

  const compare = async (id: number) => {
    setBusy(`compare-${id}`);
    try {
      const d = await diffOf(id);
      setCompared({ id, lines: diffLines(d) });
    } catch (err) {
      setResult({ tone: 'danger', text: `The comparison failed: ${getErrorMessage(err, 'the backend did not answer')}.` });
    } finally {
      setBusy(null);
    }
  };

  const restore = async (s: Snapshot) => {
    let lines: string[];
    try {
      lines = diffLines(await diffOf(s.id));
    } catch (err) {
      setResult({ tone: 'danger', text: `The snapshot could not be read: ${getErrorMessage(err, 'the backend did not answer')}.` });
      return;
    }
    if (lines.length === 0) {
      setResult({ tone: 'success', text: 'This snapshot is the configuration in force: there is nothing to restore.' });
      return;
    }
    const ok = await confirm({
      title: `Restore the configuration of ${when(s.created_at)}?`,
      body: (
        <div className="space-y-2">
          <p>These change:</p>
          <ul className="list-disc pl-4">{lines.map((l) => <li key={l}>{l}</li>)}</ul>
          <p>A snapshot of the configuration in force is taken first, so this can be undone.</p>
        </div>
      ),
      confirmLabel: 'Restore',
      destructive: true,
    });
    if (!ok) return;
    setBusy(`restore-${s.id}`);
    try {
      const res = await api.post(`config/snapshots/${s.id}/restore`, {});
      const data = res.data?.data ?? {};
      const skipped = [...(data.skipped_groups ?? []).map((g: { name: string; reason: string }) => `${g.name}: ${g.reason}`),
        ...(data.skipped_settings ?? []).map((g: { key: string; reason: string }) => `${g.key}: ${g.reason}`)];
      const failed: string[] = data.failed_files ?? [];
      const policy = data.waf_policy && !data.waf_policy.restored && !data.waf_policy.unchanged ? ` The WAF policy was not restored: ${data.waf_policy.detail}.` : '';
      const apply = describeApply(await applyToProxy(), 'Restored');
      setResult({
        tone: skipped.length || failed.length || policy ? 'warning' : apply.tone,
        text: `Restored. To undo, restore snapshot ${data.undo_snapshot}, taken just before.${policy}${skipped.length ? ` Not restored: ${skipped.join('; ')}.` : ''}${failed.length ? ` These proxy files could not be written: ${failed.join(', ')}.` : ''} ${apply.text}`,
      });
      setCompared(null);
      void queryClient.invalidateQueries();
    } catch (err) {
      setResult({ tone: 'danger', text: `The restore failed: ${getErrorMessage(err, 'the backend did not answer')}.` });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Section
      title="Configuration history"
      description="A snapshot of the settings, client groups, WAF policy and Default-deny allowlist is taken before every change to them. Restoring one makes the configuration that snapshot's exactly. The blacklists and the IP and domain exceptions are not in it: the backup above has them."
    >
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex min-w-0 flex-1 flex-col gap-1 text-sm">
            <span className="font-medium text-ink">Note for a snapshot taken now</span>
            <input
              value={note}
              maxLength={200}
              onChange={(e) => setNote(e.target.value)}
              placeholder="e.g. before the office move"
              className="h-9 rounded-control border border-line bg-surface px-3 text-sm text-ink"
            />
          </label>
          <Button onClick={() => void take()} disabled={busy !== null}>{busy === 'take' ? 'Taking...' : 'Take a snapshot now'}</Button>
        </div>
        <div aria-live="polite">{result && <p className={cn('text-sm', TONE[result.tone])}>{result.text}</p>}</div>
        {q.isPending && <p className="text-sm text-ink-muted">Reading the history...</p>}
        {q.isError && <p role="alert" className="text-sm text-danger">The history could not be read.</p>}
        {q.data && q.data.length === 0 && <p className="text-sm text-ink-muted">No snapshot yet: the first is taken before the next change.</p>}
        {q.data && q.data.length > 0 && (
          <ul aria-label="Snapshots, newest first" className="flex flex-col divide-y divide-line-subtle">
            {q.data.map((s) => (
              <li key={s.id} className="flex flex-col gap-2 py-2.5">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-sm font-medium tabular-nums text-ink">#{s.id} {when(s.created_at)}</span>
                  <span className="text-sm text-ink-secondary">{s.reason}{s.username ? `, by ${s.username}` : ''}</span>
                  {s.current && <Badge tone="success">In force</Badge>}
                  <span className="ml-auto flex gap-2">
                    <Button size="sm" onClick={() => void compare(s.id)} disabled={busy !== null}>Compare with now</Button>
                    <Button size="sm" onClick={() => void restore(s)} disabled={busy !== null || s.current}>
                      {busy === `restore-${s.id}` ? 'Restoring...' : 'Restore'}
                    </Button>
                  </span>
                </div>
                {compared?.id === s.id && (
                  compared.lines.length === 0
                    ? <p className="text-sm text-ink-muted">Nothing differs from the configuration in force.</p>
                    : (
                      <div className="text-sm text-ink-secondary">
                        <p>Restoring it would change:</p>
                        <ul className="mt-0.5 list-disc pl-4">{compared.lines.map((l) => <li key={l}>{l}</li>)}</ul>
                      </div>
                    )
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
      {dialog}
    </Section>
  );
}
