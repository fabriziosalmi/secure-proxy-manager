/**
 * SourcesSection: where the entries of a list came from (GET
 * /api/{list}/sources), one row per source with the entries it added and
 * when, and the removal of a whole source. Each entry belongs to the source
 * that added it first, so the count next to a source is exactly what its
 * removal takes away.
 */
import type { ReactNode } from 'react';
import { formatCount } from '../../lib/format';
import type { ListSource } from '../../types';
import { Button } from '../ui/Button';
import { DataTable, type Column } from '../ui/DataTable';
import { Section } from '../ui/Section';
import { addedRange, sourceDetail, sourceTitle, type ListDef } from './lists';

export interface SourcesSectionProps {
  list: ListDef;
  sources?: ListSource[] | null;
  loading: boolean;
  error: boolean;
  onRetry: () => void;
  onRemove: (s: ListSource) => void;
  className?: string;
}

/**
 * The name of a row's Remove batch button. Two pasted lists of the same size
 * would read alike, so a paste or a restore is told apart by its time.
 */
function batchLabel(s: ListSource): string {
  let label = `Remove batch: ${sourceTitle(s)}, ${formatCount(s.entries)} ${s.entries === 1 ? 'entry' : 'entries'}`;
  if (s.kind === 'paste' || s.kind === 'restore') {
    const when = sourceDetail(s);
    if (when) label += `, ${when.charAt(0).toLowerCase()}${when.slice(1)}`;
  }
  return label;
}

/** The source cell: the width the other columns leave, its text cut to fit. */
const SOURCE_CELL = 'w-full max-w-0';
/** The action cell: as wide as its button, never narrower. */
const ACTION_CELL = 'w-px whitespace-nowrap';

/** "2026-10-25 08:00 to 08:02", which may break before "to" and nowhere else. */
function AddedRange({ first, last }: { first: string; last: string }) {
  const text = addedRange(first, last);
  const at = text.indexOf(' to ');
  if (at < 0) return <span className="whitespace-nowrap">{text}</span>;
  return (
    <>
      <span className="whitespace-nowrap">{text.slice(0, at)}</span>{' '}
      <span className="whitespace-nowrap">{text.slice(at + 1)}</span>
    </>
  );
}

export function SourcesSection({ list, sources, loading, error, onRetry, onRemove, className }: SourcesSectionProps) {
  // The source column takes the width the others leave (w-full) and no more
  // (max-w-0), so a long URL or list name is cut with an ellipsis, its whole
  // text in the title, instead of pushing Remove batch out of the card. The
  // action column is as narrow as its button and never narrower. The Added
  // range may break before "to"; on a phone it moves under the source name
  // and the button reads Remove.
  const columns: Column<ListSource>[] = [
    {
      id: 'source',
      header: 'Source',
      className: SOURCE_CELL,
      cell: (s) => {
        const title = sourceTitle(s);
        const detail = sourceDetail(s);
        return (
          <div className="flex min-w-[6rem] flex-col gap-0.5">
            <span title={title} className="block truncate font-medium text-ink">{title}</span>
            {/* Up to three lines (a URL) or two, never cut on the first: a URL or the reason a source is unknown was an ellipsis at 275 px. */}
            {detail && (s.kind === 'url' && /^https?:\/\//.test(detail) ? (
              <a
                href={detail}
                target="_blank"
                rel="noopener noreferrer"
                title={detail}
                className="line-clamp-3 break-all text-xs text-ink-muted hover:text-accent hover:underline focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
              >
                {detail}
              </a>
            ) : (
              <span title={detail} className="line-clamp-2 text-xs text-ink-muted [overflow-wrap:anywhere]">{detail}</span>
            ))}
            <span className="text-xs text-ink-muted sm:hidden">Added <AddedRange first={s.first_added} last={s.last_added} /></span>
          </div>
        );
      },
    },
    { id: 'entries', header: 'Entries', align: 'right', className: 'whitespace-nowrap', cell: (s) => <span className="font-medium">{formatCount(s.entries)}</span> },
    { id: 'added', header: 'Added', hideOnPhone: true, className: 'text-ink-muted', cell: (s) => <AddedRange first={s.first_added} last={s.last_added} /> },
    {
      id: 'actions',
      header: 'Actions',
      headerHidden: true,
      align: 'right',
      className: ACTION_CELL,
      cell: (s) => (
        <Button size="sm" aria-label={batchLabel(s)} onClick={() => onRemove(s)}>
          {/* "Remove" on a phone leaves the source name room; the name of the button is the same.
              One element: two would be two flex items of the button, 6 px apart, which read as a double space. */}
          <span>Remove<span className="hidden sm:inline"> batch</span></span>
        </Button>
      ),
    },
  ];
  const empty: { title: string; description: ReactNode } = {
    title: `No ${list.plural} yet`,
    description: 'A source appears here with the first entry it adds.',
  };
  return (
    <Section
      title="Where the entries came from"
      description="Each entry keeps the source that added it first, so a list can be removed as a whole: the count is what its removal takes away."
      flush
      className={className}
    >
      <DataTable<ListSource>
        caption={`Sources of ${list.label}`}
        columns={columns}
        rows={sources ?? []}
        rowKey={(s) => (s.id === null ? 'unrecorded' : String(s.id))}
        loading={loading}
        skeletonRows={2}
        error={error ? `${list.path}/sources did not answer.` : null}
        onRetry={onRetry}
        empty={empty}
      />
    </Section>
  );
}
