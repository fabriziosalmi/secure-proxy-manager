/**
 * The hosts the clients asked for most in the last 7 days
 * (analytics/top-destinations), each opening its requests in the access log,
 * with how many of them were blocked. "Client" as everywhere else: no DNS
 * sinkhole rows and nothing from the stack's own addresses.
 */
import { Link } from 'react-router';
import type { TopDestination } from '../../types';
import { formatCount, formatShare } from '../../lib/format';
import { NO_FILTERS, writeFilters } from '../../lib/accessLog';
import { Section } from '../ui/Section';
import { DataTable, type Column } from '../ui/DataTable';

const logsOf = (host: string) => `/logs?${writeFilters({ ...NO_FILTERS, q: host }).toString()}`;

const COLUMNS: Column<TopDestination>[] = [
  {
    id: 'host',
    header: 'Destination',
    cell: (r) => (
      <Link to={logsOf(r.host)} title={r.host} className="block max-w-[22rem] truncate font-mono text-[13px] text-ink underline-offset-2 hover:underline">
        {r.host}
      </Link>
    ),
  },
  { id: 'requests', header: 'Requests', align: 'right', cell: (r) => <span className="font-medium tabular-nums">{formatCount(r.requests)}</span> },
  {
    id: 'blocked',
    header: 'Blocked',
    align: 'right',
    cell: (r) => (r.blocked > 0
      ? <span className="tabular-nums text-danger">{formatCount(r.blocked)} ({formatShare(r.blocked, r.requests)})</span>
      : <span className="text-ink-muted">None</span>),
  },
];

export function TopDestinations({ rows, loading, error, onRetry }: {
  rows?: TopDestination[] | null;
  loading: boolean;
  error: boolean;
  onRetry: () => void;
}) {
  return (
    <Section title="Most requested destinations" description="Client requests of the last 7 days, by host: the 20 asked for most." flush>
      <DataTable
        caption="Most requested destinations in the last 7 days"
        columns={COLUMNS}
        rows={rows ?? []}
        rowKey={(r) => r.host}
        loading={loading}
        error={error ? 'analytics/top-destinations did not answer.' : null}
        onRetry={onRetry}
        empty={{ title: 'No client request in the last 7 days', description: 'Destinations appear here once a device uses the proxy.' }}
      />
    </Section>
  );
}
