/**
 * DataTable: every table of records in the UI (log lines, blacklist entries,
 * clients). It owns the parts every page used to hand-roll differently:
 *
 * - a caption that names the table (visually hidden by default) and the
 *   scroll box around it, a focusable region so a keyboard user can scroll a
 *   wide table on a small screen;
 * - sortable columns: the header is a button, the sorted column carries
 *   aria-sort. Sorting is controlled (sort + onSortChange), because most
 *   lists here are sorted by the backend;
 * - an optional sticky header (stickyHeader + maxHeight);
 * - loading (skeleton rows, aria-busy, "Loading <caption>" for screen
 *   readers), error (what failed, with an optional Retry) and empty (an
 *   EmptyState saying what is missing and what to do) states;
 * - pagination as "1 to 50 of 50,772" with Previous and Next, counts written
 *   through formatCount;
 * - an optional selected row (isRowSelected), drawn in the accent tint, for
 *   a list whose selection is shown next to it. The control that selects a
 *   row lives in a cell and says its state itself (aria-pressed).
 *
 * Numbers go in right-aligned columns (align: 'right'), drawn in tabular
 * figures so they line up.
 */
import { useId, type ReactNode } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react';
import { cn } from '../../lib/utils';
import { formatRange } from '../../lib/format';
import { Button } from './Button';
import { EmptyState } from './EmptyState';

export type SortDirection = 'ascending' | 'descending';

export interface SortState {
  columnId: string;
  direction: SortDirection;
}

export interface Column<T> {
  id: string;
  /** Header text; also the sort button's name. */
  header: string;
  /** Keep the header for screen readers only (an actions column). */
  headerHidden?: boolean;
  cell: (row: T) => ReactNode;
  align?: 'left' | 'right';
  sortable?: boolean;
  /** Direction of the first sort on this column; counts read best descending. */
  firstSort?: SortDirection;
  className?: string;
}

export interface TablePagination {
  /** Index of the first row shown, from 0. */
  offset: number;
  limit: number;
  total: number;
  onChange: (offset: number) => void;
}

export interface DataTableProps<T> {
  caption: string;
  /** Show the caption above the table instead of keeping it for screen readers. */
  showCaption?: boolean;
  columns: Column<T>[];
  rows: readonly T[];
  rowKey: (row: T) => string;
  sort?: SortState;
  onSortChange?: (sort: SortState) => void;
  stickyHeader?: boolean;
  /** Height of the scroll box when the header is sticky, e.g. "480px". */
  maxHeight?: string;
  loading?: boolean;
  skeletonRows?: number;
  /** What failed, in words; shows the error state when set. */
  error?: string | null;
  onRetry?: () => void;
  empty: { title: string; description: ReactNode; action?: ReactNode };
  pagination?: TablePagination;
  /** The row shown as selected, if any. */
  isRowSelected?: (row: T) => boolean;
  className?: string;
}

export function DataTable<T>({
  caption,
  showCaption,
  columns,
  rows,
  rowKey,
  sort,
  onSortChange,
  stickyHeader,
  maxHeight,
  loading,
  skeletonRows = 5,
  error,
  onRetry,
  empty,
  pagination,
  isRowSelected,
  className,
}: DataTableProps<T>) {
  const captionId = useId();
  const cellPad = (i: number) => (i === 0 ? 'pl-5 pr-3' : i === columns.length - 1 ? 'pl-3 pr-5' : 'px-3');

  const toggleSort = (col: Column<T>) => {
    if (!onSortChange) return;
    const direction: SortDirection =
      sort?.columnId === col.id
        ? sort.direction === 'ascending' ? 'descending' : 'ascending'
        : col.firstSort ?? 'ascending';
    onSortChange({ columnId: col.id, direction });
  };

  let body: ReactNode;
  if (loading) {
    body = Array.from({ length: skeletonRows }, (_, r) => (
      <tr key={`skeleton-${r}`} aria-hidden="true" className="border-t border-line-subtle">
        {columns.map((c, i) => (
          <td key={c.id} className={cn('py-3', cellPad(i))}>
            <span className={cn('block h-3.5 rounded bg-line-subtle animate-pulse', c.align === 'right' ? 'ml-auto w-12' : 'w-3/4')} />
          </td>
        ))}
      </tr>
    ));
  } else if (error) {
    body = (
      <tr className="border-t border-line-subtle">
        <td colSpan={columns.length} className="px-5 py-8">
          <div role="alert" className="flex flex-col items-center gap-2 text-center">
            <p className="text-sm font-semibold text-danger">Could not load {caption.toLowerCase()}</p>
            <p className="max-w-md text-sm text-ink-muted">{error}</p>
            {onRetry && <Button size="sm" onClick={onRetry} className="mt-1">Retry</Button>}
          </div>
        </td>
      </tr>
    );
  } else if (rows.length === 0) {
    body = (
      <tr className="border-t border-line-subtle">
        <td colSpan={columns.length}>
          <EmptyState title={empty.title} description={empty.description} action={empty.action} />
        </td>
      </tr>
    );
  } else {
    body = rows.map((row) => {
      const selected = isRowSelected?.(row) ?? false;
      return (
        <tr
          key={rowKey(row)}
          data-selected={selected || undefined}
          className={cn('border-t border-line-subtle transition-colors', selected ? 'bg-accent-subtle' : 'hover:bg-surface-muted')}
        >
          {columns.map((c, i) => (
            <td key={c.id} className={cn('py-2.5 align-middle', cellPad(i), c.align === 'right' && 'text-right tabular-nums', c.className)}>
              {c.cell(row)}
            </td>
          ))}
        </tr>
      );
    });
  }

  const canPage = pagination && !loading && !error && rows.length > 0;

  return (
    <div className={cn('min-w-0', className)}>
      {loading && <p role="status" className="sr-only">Loading {caption.toLowerCase()}</p>}
      <div
        role="region"
        aria-labelledby={captionId}
        tabIndex={0}
        className={cn('overflow-x-auto focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent', stickyHeader && 'overflow-y-auto')}
        style={stickyHeader && maxHeight ? { maxHeight } : undefined}
      >
        <table aria-busy={loading || undefined} className="w-full border-collapse text-sm text-ink">
          <caption
            id={captionId}
            className={showCaption ? 'px-5 pb-2 text-left text-sm font-semibold text-ink' : 'sr-only'}
          >
            {caption}
          </caption>
          <thead>
            <tr className="text-left text-xs text-ink-muted">
              {columns.map((c, i) => {
                const active = sort?.columnId === c.id;
                const Icon = active ? (sort.direction === 'ascending' ? ArrowUp : ArrowDown) : ArrowUpDown;
                return (
                  <th
                    key={c.id}
                    scope="col"
                    aria-sort={active ? sort.direction : undefined}
                    className={cn(
                      'bg-surface-muted py-2.5 font-medium',
                      cellPad(i),
                      c.align === 'right' && 'text-right',
                      stickyHeader && 'sticky top-0 z-10',
                    )}
                  >
                    {c.headerHidden ? (
                      <span className="sr-only">{c.header}</span>
                    ) : c.sortable && onSortChange ? (
                      <button
                        type="button"
                        onClick={() => toggleSort(c)}
                        className={cn(
                          'inline-flex items-center gap-1 rounded-sm focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
                          active ? 'font-semibold text-ink' : 'hover:text-ink',
                        )}
                      >
                        {c.header}
                        <Icon aria-hidden="true" className={cn('h-3.5 w-3.5', !active && 'opacity-50')} />
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>{body}</tbody>
        </table>
      </div>
      {canPage && (
        <nav
          aria-label={`${caption} pages`}
          className="flex flex-wrap items-center justify-between gap-3 border-t border-line-subtle px-5 py-3"
        >
          <p aria-live="polite" className="text-[13px] text-ink-muted tabular-nums">
            {formatRange(pagination.offset, rows.length, pagination.total)}
          </p>
          <div className="flex gap-2">
            <Button
              size="sm"
              disabled={pagination.offset <= 0}
              onClick={() => pagination.onChange(Math.max(0, pagination.offset - pagination.limit))}
            >
              Previous
            </Button>
            <Button
              size="sm"
              disabled={pagination.offset + pagination.limit >= pagination.total}
              onClick={() => pagination.onChange(pagination.offset + pagination.limit)}
            >
              Next
            </Button>
          </div>
        </nav>
      )}
    </div>
  );
}
