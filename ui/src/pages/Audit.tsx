/**
 * Audit log (route /audit, Audit.dc.html): who changed what, and every
 * sign-in, newest first.
 *
 * - GET /api/audit-log, 50 a page, with ?category=all|changes|signins: the
 *   filter is applied by the backend, so the count and Newer / Older page
 *   through the filtered log, not through one page of it.
 * - Each row in plain words (lib/auditEvents): "Imported 71,140 domains from
 *   StevenBlack Unified", "Removed all 640,929 blocked domains". A key the
 *   page does not know is shown verbatim.
 * - How long rows are kept is meta.retention_days, the bound the backend's
 *   retention worker applies (pruneAuditLog).
 * - Export CSV writes the whole filtered log, with every cell that a
 *   spreadsheet would read as a formula written as text.
 */
import { useState } from 'react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Download } from 'lucide-react';
import { api, getErrorMessage } from '../lib/api';
import { auditCsv, describeAudit, type AuditKind } from '../lib/auditEvents';
import { formatCount, formatDateTime } from '../lib/format';
import { cn } from '../lib/utils';
import type { AuditEntry, AuditPageData } from '../types';
import { PageHeader } from '../components/ui/PageHeader';
import { SegmentedControl } from '../components/ui/SegmentedControl';
import { DataTable, type Column } from '../components/ui/DataTable';
import { Button } from '../components/ui/Button';

const PAGE_SIZE = 50;
const EXPORT_PAGE = 200; // the backend's largest page
const EXPORT_MAX_PAGES = 1000;

type Category = 'all' | 'changes' | 'signins';

const CATEGORIES: { value: Category; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'changes', label: 'Changes' },
  { value: 'signins', label: 'Sign-ins' },
];

const EMPTY: Record<Category, { title: string; description: string }> = {
  all: { title: 'No event recorded yet', description: 'Sign-ins and changes to settings and lists appear here as they happen.' },
  changes: { title: 'No change recorded', description: 'Changes to settings, lists and the proxy appear here once someone makes one.' },
  signins: { title: 'No sign-in recorded', description: 'Every sign-in, failed sign-in and sign-out appears here.' },
};

const KIND_STYLE: Record<AuditKind, string> = {
  change: 'bg-accent-subtle text-accent',
  signin: 'bg-line-subtle text-ink-muted',
  'signin-failed': 'bg-warning-subtle text-warning',
};

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function fetchWholeLog(category: Category): Promise<AuditEntry[]> {
  const out: AuditEntry[] = [];
  for (let page = 0, offset = 0; page < EXPORT_MAX_PAGES; page++) {
    // Paced under the nginx limit of 20 requests per second.
    if (page > 0) await pause(55);
    const r = await api.get('audit-log', { params: { limit: EXPORT_PAGE, offset, category } });
    const rows = (r.data?.data ?? []) as AuditEntry[];
    out.push(...rows);
    offset += rows.length;
    const total = r.data?.meta?.total;
    if (rows.length < EXPORT_PAGE || (typeof total === 'number' && offset >= total)) break;
  }
  return out;
}

function timeZone(): string | null {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || null;
  } catch {
    return null;
  }
}

export function Audit() {
  const [category, setCategory] = useState<Category>('all');
  const [offset, setOffset] = useState(0);
  const [exporting, setExporting] = useState(false);

  const log = useQuery<AuditPageData>({
    queryKey: ['audit-log', category, offset],
    queryFn: () => api.get('audit-log', { params: { limit: PAGE_SIZE, offset, category } }).then((r) => r.data),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });
  const rows = log.data?.data ?? [];
  const total = log.data?.meta?.total ?? 0;
  const retention = log.data?.meta?.retention_days;

  const pick = (c: Category) => {
    setCategory(c);
    setOffset(0);
  };

  const exportCsv = async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const all = await fetchWholeLog(category);
      const url = URL.createObjectURL(new Blob([auditCsv(all)], { type: 'text/csv' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = `audit-log-${category}-${new Date().toISOString().slice(0, 10)}.csv`;
      link.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported ${formatCount(all.length)} ${all.length === 1 ? 'event' : 'events'}`);
    } catch (err) {
      toast.error(getErrorMessage(err, 'Could not export the audit log'));
    } finally {
      setExporting(false);
    }
  };

  const columns: Column<AuditEntry>[] = [
    {
      id: 'time',
      header: 'Time',
      className: 'whitespace-nowrap font-mono text-xs text-ink-muted',
      cell: (e) => formatDateTime(e.timestamp),
    },
    {
      id: 'user',
      header: 'User',
      className: 'whitespace-nowrap',
      cell: (e) => e.username || <span className="text-ink-muted">No user recorded</span>,
    },
    {
      id: 'event',
      header: 'Event',
      className: 'min-w-[14rem]',
      cell: (e) => {
        const d = describeAudit(e);
        return (
          <span className={cn('inline-block rounded-md px-2 py-0.5 text-xs font-medium [overflow-wrap:anywhere]', KIND_STYLE[d.kind])}>
            {d.event}
          </span>
        );
      },
    },
    {
      id: 'details',
      header: 'Details',
      className: 'min-w-[12rem] text-[13px] text-ink-muted [overflow-wrap:anywhere]',
      cell: (e) => describeAudit(e).details ?? 'No details',
    },
  ];

  const zone = timeZone();
  let description = 'Who changed what, and every sign-in.';
  if (typeof retention === 'number') description += ` Kept for ${formatCount(retention)} days.`;
  else if (log.isSuccess) description += ' How long events are kept is not reported.';

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        eyebrow="System"
        title="Audit log"
        description={description}
        actions={
          <Button icon={<Download />} disabled={exporting || total === 0} onClick={() => { void exportCsv(); }}>
            {exporting ? 'Exporting...' : 'Export CSV'}
          </Button>
        }
      />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <SegmentedControl<Category> label="Show" options={CATEGORIES} value={category} onChange={pick} />
        <p className="text-[13px] text-ink-muted">
          Newest first. Times are in your time zone{zone ? ` (${zone})` : ''}.
        </p>
      </div>

      <section aria-label="Events" className="min-w-0 overflow-hidden rounded-panel border border-line bg-surface">
        <DataTable<AuditEntry>
          caption="Audit events"
          columns={columns}
          rows={rows}
          rowKey={(e) => String(e.id)}
          loading={log.isPending}
          error={log.isError ? 'The audit log did not answer.' : null}
          onRetry={() => { void log.refetch(); }}
          empty={EMPTY[category]}
          pagination={{ offset, limit: PAGE_SIZE, total, onChange: setOffset, previousLabel: 'Newer', nextLabel: 'Older' }}
        />
      </section>
    </div>
  );
}
