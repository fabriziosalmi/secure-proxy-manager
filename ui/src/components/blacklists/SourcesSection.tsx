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

export function SourcesSection({ list, sources, loading, error, onRetry, onRemove, className }: SourcesSectionProps) {
  const columns: Column<ListSource>[] = [
    {
      id: 'source',
      header: 'Source',
      cell: (s) => {
        const detail = sourceDetail(s);
        return (
          <div className="flex min-w-0 flex-col gap-0.5">
            <span className="font-medium text-ink">{sourceTitle(s)}</span>
            {detail && (
              <span title={detail} className="block max-w-[18rem] truncate text-xs text-ink-muted sm:max-w-[24rem]">{detail}</span>
            )}
          </div>
        );
      },
    },
    { id: 'entries', header: 'Entries', align: 'right', cell: (s) => <span className="font-medium">{formatCount(s.entries)}</span> },
    { id: 'added', header: 'Added', className: 'whitespace-nowrap text-ink-muted', cell: (s) => addedRange(s.first_added, s.last_added) },
    {
      id: 'actions',
      header: 'Actions',
      headerHidden: true,
      align: 'right',
      cell: (s) => (
        <Button size="sm" aria-label={`Remove batch: ${sourceTitle(s)}, ${formatCount(s.entries)} ${s.entries === 1 ? 'entry' : 'entries'}`} onClick={() => onRemove(s)}>
          Remove batch
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
