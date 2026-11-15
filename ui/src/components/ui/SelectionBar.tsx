/**
 * SelectionBar: what a table's checked rows can do, between its search and
 * the table, so it is in view while the rows at the top are checked. It says
 * how many rows are checked, offers the action on them, and clears the
 * checks. It is not drawn while none is checked; the count is announced as it
 * changes.
 */
import { Button } from './Button';
import { formatCount } from '../../lib/format';

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
}

export function SelectionBar({ count, one, many, actionLabel, onAction, onClear, busy }: SelectionBarProps) {
  return (
    <div aria-live="polite">
      {count > 0 && (
        <div className="flex flex-wrap items-center gap-3 border-y border-line-subtle bg-accent-subtle px-5 py-2">
          <span className="text-sm font-medium tabular-nums text-ink">{formatCount(count)} {count === 1 ? one : many} selected on this page</span>
          <span className="ml-auto flex gap-2">
            <Button size="sm" variant="danger-outline" disabled={busy} onClick={onAction}>{actionLabel(count)}</Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={onClear}>Clear selection</Button>
          </span>
        </div>
      )}
    </div>
  );
}
