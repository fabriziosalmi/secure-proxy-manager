/**
 * SaveBar: the foot of a Settings section. With unsaved changes it is a
 * sticky bar ("2 unsaved changes", Discard, Save section). After a save it
 * becomes one status line that says what actually happened: applied to the
 * proxy at a time, not confirmed in time, refused by the proxy, files that
 * could not be written, or where else the change takes effect. Nothing is
 * drawn when the section is clean and has no result to report.
 */
import { CircleCheck, TriangleAlert, OctagonAlert } from 'lucide-react';
import { Button } from '../ui/Button';
import { cn } from '../../lib/utils';
import { describeSave, type SaveResult } from '../../lib/settingsSave';

export interface SaveBarProps {
  changes: number;
  saving: boolean;
  result?: SaveResult;
  /** Label of a field, for the "needs attention" line. */
  labelOf: (key: string) => string;
  onSave: () => void;
  onDiscard: () => void;
  /** Ask the proxy to apply the saved configuration again. */
  onRetryApply?: () => void;
}

type Tone = ReturnType<typeof describeSave>['tone'];

const TONE: Record<Tone, { box: string; Icon: typeof CircleCheck }> = {
  success: { box: 'border-success-subtle bg-success-subtle text-success', Icon: CircleCheck },
  warning: { box: 'border-warning-line bg-warning-subtle text-warning-ink', Icon: TriangleAlert },
  danger: { box: 'border-danger-line bg-danger-subtle text-danger', Icon: OctagonAlert },
};

export function SaveBar({ changes, saving, result, labelOf, onSave, onDiscard, onRetryApply }: SaveBarProps) {
  if (changes > 0 || saving) {
    const invalid = result?.kind === 'invalid' ? result : undefined;
    const fields = invalid?.fields ?? [];
    let text = changes === 1 ? '1 unsaved change' : `${changes} unsaved changes`;
    if (fields.length) text = `Not saved: ${fields.length === 1 ? `${labelOf(fields[0])} needs` : `${fields.length} fields need`} attention`;
    else if (invalid?.outside || result?.kind === 'error') text = `Not saved: ${invalid?.outside ?? (result as { message: string }).message}`;
    if (saving) text = 'Saving...';
    return (
      <div
        data-testid="save-bar"
        className={cn(
          'sticky bottom-0 z-10 -mx-4 flex flex-wrap items-center justify-between gap-3 border-t px-4 py-3 lg:mx-0 lg:rounded-panel lg:border',
          fields.length || result?.kind === 'error' || invalid?.outside ? 'border-danger-line bg-danger-subtle' : 'border-line bg-surface-muted',
        )}
      >
        <p role="status" className={cn('text-sm', fields.length || result?.kind === 'error' || invalid?.outside ? 'text-danger' : 'text-ink-secondary')}>{text}</p>
        <div className="flex gap-2">
          <Button onClick={onDiscard} disabled={saving}>Discard</Button>
          <Button variant="primary" onClick={onSave} disabled={saving}>{saving ? 'Saving...' : 'Save section'}</Button>
        </div>
      </div>
    );
  }
  if (!result || result.kind === 'invalid') return null;
  const d = describeSave(result);
  const t = TONE[d.tone];
  return (
    <div data-testid="save-result" className={cn('flex flex-wrap items-start gap-3 rounded-panel border px-4 py-3', t.box)}>
      <t.Icon aria-hidden="true" className="mt-px h-5 w-5 shrink-0" strokeWidth={1.75} />
      <div role="status" className="flex min-w-0 flex-1 flex-col gap-1 text-sm">
        {d.lines.map((l, i) => <p key={i} className={i === 0 ? 'font-medium' : undefined}>{l}</p>)}
      </div>
      {d.retry && onRetryApply && <Button size="sm" onClick={onRetryApply}>Apply again</Button>}
    </div>
  );
}
