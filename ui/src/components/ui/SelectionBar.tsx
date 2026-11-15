/**
 * SelectionBar: what a table's checked rows can do, between its search and
 * the table, so it is in view while the rows at the top are checked. It says
 * how many rows are checked, offers the action on them, and clears the
 * checks; the count is announced as it changes. With none checked it keeps
 * its height and says what checking does (hint), so the table does not move
 * under the pointer when the first row is checked.
 */
import { Button } from './Button';
import { formatCount } from '../../lib/format';
import { cn } from '../../lib/utils';

export interface SelectionBarProps {
  count: number;
  /** "entry" / "entries": what a row is. */
  one: string;
  many: string;
  /** The action's label for n rows: "Remove 3". */
  actionLabel: (n: number) => string;
  onAction: () => void;
  onClear: () => void;
  busy?: boolean;
  /** What checking rows does, shown while none is checked. */
  hint: string;
}

export function SelectionBar({ count, one, many, actionLabel, onAction, onClear, busy, hint }: SelectionBarProps) {
  return (
    <div aria-live="polite" className={cn('flex min-h-11 flex-wrap items-center gap-3 border-y border-line-subtle px-5 py-1.5', count > 0 ? 'bg-accent-subtle' : 'bg-surface')}>
      {count > 0 ? (
        <>
          <span className="text-sm font-medium tabular-nums text-ink">{formatCount(count)} {count === 1 ? one : many} selected on this page</span>
          <span className="ml-auto flex gap-2">
            <Button size="sm" variant="danger-outline" disabled={busy} onClick={onAction}>{actionLabel(count)}</Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={onClear}>Clear selection</Button>
          </span>
        </>
      ) : (
        <span className="text-[13px] text-ink-muted">{hint}</span>
      )}
    </div>
  );
}
