/**
 * Client trajectories (Analytics): clients whose WAF signals over a day read
 * as a compromised host, from GET /api/waf/trajectories; a row opens the
 * client's signals of that day, from GET /api/waf/trajectories/{id}.
 *
 * The phases are those of what a compromised host does on the way out:
 * arrival (it reached a typosquatted name), contact (it called out like an
 * implant: a generated name, regular check-ins, a TLS name other than the
 * one asked for), action (many hosts in a minute, tunnels, secrets or data
 * on the way out). Signals that need corroboration on their own (regular
 * check-ins, a burst of hosts) do not make a trajectory as a pair.
 */
import { useId, useState } from 'react';
import { createPortal } from 'react-dom';
import { useQuery } from '@tanstack/react-query';
import { X } from 'lucide-react';
import { getData } from '../../lib/api';
import { formatDateTime } from '../../lib/format';
import { wafCategoryLabel } from '../../lib/wafCategories';
import { useModal } from '../../hooks/useModal';
import type { WafTrajectory, WafTrajectoryDetail } from '../../types';
import { Badge, type BadgeTone } from '../ui/Badge';
import { Button, IconButton } from '../ui/Button';
import { DataTable, type Column } from '../ui/DataTable';
import { Notice } from '../ui/Notice';
import { Section } from '../ui/Section';

const PHASE_TONE: Record<string, BadgeTone> = { arrival: 'warning', contact: 'warning', action: 'danger' };

const RULE_TEXT: Record<string, string> = {
  order: 'One stage followed another',
  breadth: 'Three different signals',
};

function Phases({ phases }: { phases: string[] }) {
  return (
    <span className="flex flex-wrap gap-1">
      {phases.map((p) => <Badge key={p} tone={PHASE_TONE[p] ?? 'neutral'}>{p}</Badge>)}
    </span>
  );
}

function categoryNames(categories: string[]): string {
  return categories.map((c) => wafCategoryLabel(c).label).join(', ');
}

export function Trajectories({ rows, loading, error, onRetry, gdpr }: {
  rows?: WafTrajectory[] | null;
  loading: boolean;
  error: boolean;
  onRetry: () => void;
  /** GDPR mode is on: no new trajectory is read. */
  gdpr: boolean;
}) {
  const [open, setOpen] = useState<WafTrajectory | null>(null);
  const columns: Column<WafTrajectory>[] = [
    { id: 'client', header: 'Client', cell: (r) => <span className="font-mono">{r.client_ip}</span> },
    { id: 'closed', header: 'Seen', cell: (r) => <span className="tabular-nums">{formatDateTime(r.closed)}</span> },
    { id: 'phases', header: 'Stages', cell: (r) => <Phases phases={r.phases} /> },
    { id: 'signals', header: 'Signals', cell: (r) => categoryNames(r.categories), hideOnPhone: true },
    {
      id: 'open',
      header: 'Details',
      headerHidden: true,
      align: 'right',
      cell: (r) => (
        <Button size="sm" variant="secondary" onClick={() => setOpen(r)} aria-label={`Signals of ${r.client_ip}`}>
          Signals
        </Button>
      ),
    },
  ];
  return (
    <Section
      title="Client trajectories"
      description="Clients whose WAF signals over a day read as a compromised host: it reached a typosquatted name, called out like an implant, or sent secrets or data out. Last 7 days, by the time the pattern was complete."
      flush
    >
      {gdpr && (
        <div className="px-5 pb-3">
          <Notice title="Not read in GDPR mode">
            GDPR mode stores a client as its network, which would read several devices as one, so no new trajectory is
            read while it is on. Those found before are shown masked.
          </Notice>
        </div>
      )}
      <DataTable
        caption="Client trajectories in the last 7 days"
        columns={columns}
        rows={rows ?? []}
        rowKey={(r) => String(r.id)}
        loading={loading}
        error={error ? 'waf/trajectories did not answer.' : null}
        onRetry={onRetry}
        isRowSelected={(r) => r.id === open?.id}
        empty={{
          title: 'No client trajectory in the last 7 days',
          description: 'A client appears here when its WAF signals over a day follow one another, such as a typosquatted name and then a secret sent out.',
        }}
      />
      {open && <TrajectoryDrawer trajectory={open} onClose={() => setOpen(null)} />}
    </Section>
  );
}

function TrajectoryDrawer({ trajectory, onClose }: { trajectory: WafTrajectory; onClose: () => void }) {
  const modalRef = useModal<HTMLDivElement>(true, onClose);
  const headingId = useId();
  const detail = useQuery({
    queryKey: ['waf-trajectory', trajectory.id],
    queryFn: () => getData<WafTrajectoryDetail>(`waf/trajectories/${trajectory.id}`),
  });
  const t = detail.data?.trajectory ?? trajectory;
  // Rendered into document.body, as the client drawer is: a fixed overlay is
  // laid out against the viewport only with no transformed ancestor.
  return createPortal(
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true" aria-labelledby={headingId}>
      <div className="absolute inset-0 bg-black/50" onClick={onClose} aria-hidden="true" />
      <div ref={modalRef} className="relative h-full w-full max-w-lg overflow-y-auto border-l border-line bg-surface text-ink shadow-2xl">
        <div className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-line-subtle bg-surface px-5 py-3">
          <h2 id={headingId} className="truncate font-mono text-base font-semibold">{t.client_ip}</h2>
          <IconButton aria-label="Close" icon={<X />} onClick={onClose} />
        </div>
        <div className="flex flex-col gap-4 px-5 py-4">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-ink-muted">Why</dt>
            <dd>{RULE_TEXT[t.rule] ?? t.rule}</dd>
            <dt className="text-ink-muted">First signal</dt>
            <dd className="tabular-nums">{formatDateTime(t.start)}</dd>
            <dt className="text-ink-muted">Pattern complete</dt>
            <dd className="tabular-nums">{formatDateTime(t.closed)}</dd>
            <dt className="text-ink-muted">Stages</dt>
            <dd><Phases phases={t.phases} /></dd>
          </dl>
          <h3 className="text-sm font-semibold">Signals of that day, in order</h3>
          {detail.isLoading && <p className="text-sm text-ink-muted" role="status">Loading signals…</p>}
          {detail.isError && (
            <Notice tone="danger" title="Signals not loaded" action={<Button size="sm" variant="secondary" onClick={() => void detail.refetch()}>Retry</Button>}>
              waf/trajectories/{t.id} did not answer.
            </Notice>
          )}
          {detail.data && (
            <ol className="flex flex-col gap-2">
              {detail.data.signals.map((s, i) => (
                <li key={`${s.event_id}-${s.category}-${i}`} className="rounded-md border border-line-subtle px-3 py-2 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="tabular-nums text-ink-muted">{formatDateTime(s.at)}</span>
                    <Badge tone={PHASE_TONE[s.phase] ?? 'neutral'}>{s.phase}</Badge>
                    <span className="font-medium">{wafCategoryLabel(s.category).label}</span>
                    {s.observed && <Badge>Log only</Badge>}
                    {s.blocked && <Badge tone="danger">Blocked</Badge>}
                  </div>
                  {s.host && <div className="mt-1 break-all font-mono text-ink-muted">{s.host}</div>}
                </li>
              ))}
            </ol>
          )}
          {detail.data?.truncated && (
            <p className="text-sm text-ink-muted">Only the first {detail.data.signals.length} signals of that day are shown.</p>
          )}
        </div>
      </div>
    </div>,
    document.body,
  );
}
