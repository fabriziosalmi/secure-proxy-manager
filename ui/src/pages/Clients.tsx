/**
 * Clients: the sources that sent requests through the proxy in the last 7
 * days (Clients.dc.html). Every number comes from /api/clients/statistics
 * and /api/clients/{ip}/details.
 *
 * The backend marks the stack's own addresses as internal (loopback, the
 * Docker host, the backend, the proxy): they are hidden unless the viewer
 * turns them on, and the Overview never counts them. On a wide screen the
 * selected client's detail sits next to the table; below lg it opens in a
 * drawer. On a phone the table keeps its columns and scrolls sideways inside
 * its own region, so the page itself never does.
 */
import { createPortal } from 'react-dom';
import { useId, useMemo, useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router';
import { X } from 'lucide-react';
import { ClientSetup } from '../components/ClientSetup';
import { PageHeader } from '../components/ui/PageHeader';
import { Section } from '../components/ui/Section';
import { DataTable, type Column, type SortState } from '../components/ui/DataTable';
import { SearchInput } from '../components/ui/SearchInput';
import { Switch } from '../components/ui/Switch';
import { Button, IconButton } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { ShareBar } from '../components/ui/ShareBar';
import { shareText } from '../lib/share';
import { useModal } from '../hooks/useModal';
import { useMediaQuery, DESKTOP_QUERY } from '../hooks/useMediaQuery';
import { api, getData } from '../lib/api';
import { formatCount, formatWhen, formatWhenExact } from '../lib/format';
import { cn } from '../lib/utils';
import type { ClientsData, ClientStat, ClientDetail, ClientDomain, ClientRecent } from '../types';
import { tableKind } from '../lib/clientKind';

/** Where the "Show internal addresses" choice is kept, per viewer. */
export const SHOW_INTERNAL_KEY = 'spm.clients.showInternal';

function readShowInternal(): boolean {
  try {
    return window.localStorage.getItem(SHOW_INTERNAL_KEY) === 'true';
  } catch {
    return false;
  }
}

function writeShowInternal(on: boolean) {
  try {
    window.localStorage.setItem(SHOW_INTERNAL_KEY, on ? 'true' : 'false');
  } catch {
    // Storage blocked (private window, previews): the choice lasts for this visit.
  }
}

const plural = (n: number, one: string, many: string) => `${formatCount(n)} ${n === 1 ? one : many}`;

/** "09:21" today, "Yesterday 23:55", "Sun 25 23:55" in the last week, "2026-10-21 09:21" before. */
function shortTime(ts: string): string {
  return ts ? formatWhen(ts, { style: 'glance' }) : 'Not recorded';
}

const clientKey = (c: ClientStat): string => c.network || c.ip_address;

function sortRows(rows: ClientStat[], sort: SortState): ClientStat[] {
  const key = sort.columnId === 'blocked' ? 'blocked' : 'requests';
  const dir = sort.direction === 'ascending' ? 1 : -1;
  return [...rows].sort((a, b) => (a[key] - b[key]) * dir || clientKey(a).localeCompare(clientKey(b)));
}

export function Clients() {
  const isDesktop = useMediaQuery(DESKTOP_QUERY);
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState<SortState>({ columnId: 'requests', direction: 'descending' });
  const [showInternal, setShowInternal] = useState(readShowInternal);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [setupOpen, setSetupOpen] = useState(false);
  const switchLabelId = useId();
  const setupId = useId();

  const clients = useQuery<ClientsData | null>({
    queryKey: ['clients', 'statistics'],
    // A list endpoint: the collection is under data and its counts under
    // meta, so the page needs the whole body (getData would unwrap it to the
    // bare array).
    queryFn: () => api.get('clients/statistics').then((r) => r.data ?? null),
    refetchInterval: 30_000,
  });

  const all = useMemo(() => clients.data?.data ?? [], [clients.data]);
  const internalTotal = clients.data?.meta?.internal ?? all.filter((c) => c.internal).length;
  const clientTotal = clients.data?.meta?.total;

  const rows = useMemo(() => {
    const t = search.trim().toLowerCase();
    const visible = all.filter(
      (c) => (showInternal || !c.internal) && (!t || c.ip_address.toLowerCase().includes(t) || (c.network?.toLowerCase().includes(t) ?? false)),
    );
    return sortRows(visible, sort);
  }, [all, search, showInternal, sort]);

  // On a wide screen the panel always shows a client: the one picked, or the
  // first row while none is (or the picked one is filtered out).
  const panelIp = isDesktop
    ? (selectedIp && rows.some((r) => clientKey(r) === selectedIp) ? selectedIp : (rows[0] ? clientKey(rows[0]) : null))
    : null;
  const activeIp = isDesktop ? panelIp : selectedIp;
  const activeRow = all.find((c) => clientKey(c) === activeIp);

  const toggleInternal = (on: boolean) => {
    setShowInternal(on);
    writeShowInternal(on);
  };

  const columns: Column<ClientStat>[] = [
    {
      id: 'client',
      header: 'Client',
      cell: (c) => {
        const key = clientKey(c);
        const sub = [
          c.network,
          typeof c.addresses === 'number' ? plural(c.addresses, 'address', 'addresses') : null,
          tableKind(c.kind),
        ].filter(Boolean).join(' · ');
        return (
          <div className="flex min-w-0 flex-col gap-0.5">
            <button
              type="button"
              onClick={() => setSelectedIp(key)}
              aria-pressed={isDesktop ? key === activeIp : undefined}
              aria-haspopup={isDesktop ? undefined : 'dialog'}
              className="self-start rounded-sm text-left font-mono text-[13px] font-medium text-ink hover:text-accent hover:underline focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
            >
              {c.ip_address}
            </button>
            {sub && <span className="text-xs text-ink-muted">{sub}</span>}
          </div>
        );
      },
    },
    { id: 'requests', header: 'Requests', align: 'right', sortable: true, firstSort: 'descending', cell: (c) => <span className="font-medium">{formatCount(c.requests)}</span> },
    {
      id: 'blocked',
      header: 'Blocked',
      align: 'right',
      sortable: true,
      firstSort: 'descending',
      cell: (c) => <span className={cn('font-medium', c.blocked > 0 ? 'text-danger' : 'text-ink-muted')}>{formatCount(c.blocked)}</span>,
    },
    { id: 'share', header: 'Share blocked', className: 'w-40', cell: (c) => <ShareBar part={c.blocked} total={c.requests} trackClassName="min-w-16" textClassName="w-12 text-right text-[13px]" /> },
    {
      id: 'last',
      header: 'Last request',
      className: 'whitespace-nowrap text-ink-muted',
      cell: (c) => <span title={c.last_seen ? formatWhenExact(c.last_seen) : undefined}>{shortTime(c.last_seen)}</span>,
    },
  ];

  const connect = (
    <Button aria-expanded={setupOpen} aria-controls={setupId} onClick={() => setSetupOpen((o) => !o)}>
      Connect a device
    </Button>
  );

  let empty: { title: string; description: ReactNode; action?: ReactNode };
  if (search.trim()) {
    empty = { title: `No client matches "${search.trim()}"`, description: 'Clear the filter to see every client.' };
  } else if (all.length > 0 && !showInternal) {
    empty = {
      title: 'No devices in the last 7 days',
      description: `Only internal addresses sent requests (${formatCount(internalTotal)}). Turn on "Show internal addresses" to see them.`,
    };
  } else {
    empty = {
      title: 'No client traffic in the last 7 days',
      description: 'Devices appear here once they send requests through the proxy.',
      action: !setupOpen ? <Button size="sm" onClick={() => setSetupOpen(true)} aria-controls={setupId}>Connect a device</Button> : undefined,
    };
  }

  const footer = clients.data ? footerText({ rows, all, showInternal, internalTotal, clientTotal, filtered: search.trim() !== '' }) : null;
  const hasNetworks = all.some((c) => Boolean(c.network));

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        eyebrow="Traffic"
        title="Clients"
        description="Devices that sent traffic through the proxy in the last 7 days."
        actions={connect}
      />

      <div id={setupId} hidden={!setupOpen}>
        {setupOpen && (
          <Section title="Connect a device" description="Point the device at the proxy; it appears in this list after its first request.">
            <ClientSetup />
          </Section>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <SearchInput
          label={hasNetworks ? 'Filter clients by network or IP address' : 'Filter clients by IP address'}
          placeholder={hasNetworks ? 'Filter by network or IP address' : 'Filter by IP address'}
          value={search}
          onChange={setSearch}
          className="w-full sm:w-auto sm:flex-[1_1_280px] sm:max-w-[360px]"
        />
        <div className="flex h-9 items-center gap-2.5 rounded-control border border-line-strong bg-surface px-3 text-sm text-ink-secondary">
          <Switch labelledBy={switchLabelId} checked={showInternal} onChange={toggleInternal} />
          <span id={switchLabelId}>Show internal addresses ({formatCount(internalTotal)})</span>
        </div>
      </div>

      <div className="flex flex-wrap items-start gap-4">
        <Section title="Last 7 days" flush className="min-w-0 flex-[3_1_560px]">
          <DataTable<ClientStat>
            caption="Clients in the last 7 days"
            columns={columns}
            rows={rows}
            rowKey={clientKey}
            sort={sort}
            onSortChange={setSort}
            loading={clients.isPending}
            error={clients.isError ? 'clients/statistics did not answer.' : null}
            onRetry={() => { void clients.refetch(); }}
            empty={empty}
            isRowSelected={isDesktop ? (c) => clientKey(c) === activeIp : undefined}
          />
          {footer && <p className="border-t border-line-subtle px-5 py-3 text-[13px] text-ink-muted">{footer}</p>}
        </Section>

        {isDesktop && panelIp && (
          <Section title={panelIp} className="min-w-0 flex-[2_1_360px] [&_h2]:font-mono" flush>
            <ClientDetailBody ip={panelIp} row={activeRow} />
          </Section>
        )}
      </div>

      {!isDesktop && selectedIp && (
        <ClientDrawer ip={selectedIp} row={activeRow} onClose={() => setSelectedIp(null)} />
      )}
    </div>
  );
}

function footerText({ rows, all, showInternal, internalTotal, clientTotal, filtered }: {
  rows: ClientStat[];
  all: ClientStat[];
  showInternal: boolean;
  internalTotal: number;
  clientTotal?: number;
  filtered: boolean;
}): string {
  const parts: string[] = [];
  const listedClients = all.filter((c) => !c.internal).length;
  const shown = filtered ? 'match the filter' : 'shown';
  if (showInternal) {
    const internalShown = rows.filter((c) => c.internal).length;
    parts.push(`${plural(rows.length, 'address', 'addresses')} ${filtered && rows.length === 1 ? 'matches the filter' : shown}, ${formatCount(internalShown)} of them internal.`);
    parts.push('Internal traffic is not counted in any statistic.');
  } else {
    parts.push(`${plural(rows.length, 'client', 'clients')} ${filtered && rows.length === 1 ? 'matches the filter' : shown}.`);
    if (internalTotal > 0) {
      parts.push(`${plural(internalTotal, 'internal address is', 'internal addresses are')} hidden and not counted in any statistic.`);
    }
  }
  if (typeof clientTotal === 'number' && clientTotal > listedClients) {
    parts.push(`The list holds the ${formatCount(listedClients)} with the most requests of ${plural(clientTotal, 'client', 'clients')}.`);
  }
  return parts.join(' ');
}

const DEST_COLUMNS: Column<ClientDomain>[] = [
  {
    id: 'host',
    header: 'Destination',
    cell: (d) => <code title={d.destination} className="block max-w-[11rem] truncate font-mono text-xs sm:max-w-[14rem]">{d.destination}</code>,
  },
  { id: 'requests', header: 'Requests', align: 'right', cell: (d) => formatCount(d.requests) },
  {
    id: 'blocked',
    header: 'Blocked',
    align: 'right',
    cell: (d) => <span className={d.blocked > 0 ? 'text-danger' : 'text-ink-muted'}>{formatCount(d.blocked)}</span>,
  },
];

/** One line on the blocked requests logged before reasons were recorded. */
function unclassifiedNote(unclassified: number, blocked: number): string {
  const tail = 'logged before the proxy recorded why it blocked a request, so the rule is not known.';
  if (unclassified >= blocked) {
    return blocked === 1 ? `The blocked request was ${tail}` : `All ${formatCount(blocked)} blocked requests were ${tail}`;
  }
  return `${formatCount(unclassified)} of the ${formatCount(blocked)} blocked requests ${unclassified === 1 ? 'was' : 'were'} ${tail}`;
}

function RecentReason({ r }: { r: ClientRecent }) {
  if (r.blocked === undefined) return null;
  if (!r.blocked) return <span className="text-xs text-ink-muted">Not blocked</span>;
  if (!r.reason_label) return <Badge tone="danger">Blocked</Badge>;
  return <Badge tone={r.reason === 'unclassified' ? 'neutral' : 'danger'}>{r.reason_label}</Badge>;
}

/**
 * The detail of one client: its first and last request, counts, top
 * destinations and recent requests. The counts cover every request logged
 * for the address, not only the table's 7 days; when they differ from the
 * row, a line says so.
 */
function ClientDetailBody({ ip, row }: { ip: string; row?: ClientStat }) {
  const detail = useQuery<ClientDetail | null>({
    queryKey: ['client-details', ip],
    queryFn: () => getData<ClientDetail>(`clients/${encodeURIComponent(ip)}/details`),
  });
  const info = detail.data;

  if (detail.isPending) {
    return (
      <div className="px-5 pb-5">
        <span aria-hidden="true" className="block h-24 rounded-md bg-line-subtle animate-pulse" />
        <span role="status" className="sr-only">Loading the detail of {ip}</span>
      </div>
    );
  }
  if (detail.isError || !info) {
    return (
      <div className="flex flex-col items-start gap-2 px-5 pb-5" role="alert">
        <p className="text-sm text-ink-muted">Not reported: clients/{ip}/details did not answer.</p>
        <Button size="sm" onClick={() => { void detail.refetch(); }}>Retry</Button>
      </div>
    );
  }

  const share = shareText(info.blocked, info.total_requests);
  const unclassified = info.blocked_by_reason?.find((r) => r.reason === 'unclassified')?.count ?? 0;
  const widerThanRow = row !== undefined && row.requests !== info.total_requests;
  const networkCidr = info.network || row?.network || (ip.includes('/') ? ip : undefined);
  const isNetwork = Boolean(networkCidr);
  const logTarget = networkCidr || ip;
  const detailSub = [
    info.network,
    typeof info.addresses === 'number' ? plural(info.addresses, 'address', 'addresses') : null,
    info.kind,
  ].filter(Boolean).join(' · ');

  return (
    <div className="flex flex-col gap-5 pb-5">
      <div className="flex flex-col gap-1 px-5 text-[13px] text-ink-muted">
        {detailSub && <p>{detailSub}</p>}
        {info.first_seen ? (
          // One row each, never broken: a date used to wrap away from its time.
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
            <dt>First request</dt>
            <dd className="whitespace-nowrap text-ink-secondary" title={formatWhenExact(info.first_seen)}>{shortTime(info.first_seen)}</dd>
            <dt>Last request</dt>
            <dd className="whitespace-nowrap text-ink-secondary" title={info.last_seen ? formatWhenExact(info.last_seen) : undefined}>{info.last_seen ? shortTime(info.last_seen) : 'Not recorded'}</dd>
          </dl>
        ) : <p>No request recorded</p>}
        <Link
          to={`/logs?client=${encodeURIComponent(logTarget)}`}
          className="self-start rounded-sm font-semibold text-accent hover:underline focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
        >
          {isNetwork ? 'Show requests from this network in the access log' : "Show this client's requests in the access log"}
        </Link>
      </div>

      <dl className="grid grid-cols-3 gap-3 px-5">
        <div className="flex min-w-0 flex-col gap-0.5">
          <dt className="text-xs text-ink-muted">Requests</dt>
          <dd className="text-xl font-semibold tabular-nums text-ink">{formatCount(info.total_requests)}</dd>
        </div>
        <div className="flex min-w-0 flex-col gap-0.5">
          <dt className="text-xs text-ink-muted">Blocked</dt>
          <dd className={cn('text-xl font-semibold tabular-nums', info.blocked > 0 ? 'text-danger' : 'text-ink')}>{formatCount(info.blocked)}</dd>
        </div>
        <div className="flex min-w-0 flex-col gap-0.5">
          <dt className="text-xs text-ink-muted">Share blocked</dt>
          <dd className="text-xl font-semibold tabular-nums text-ink">{share ?? 'No requests'}</dd>
        </div>
      </dl>

      {(widerThanRow || unclassified > 0) && (
        <div className="flex flex-col gap-1 px-5 text-[13px] text-ink-muted">
          {widerThanRow && <p>These counts cover every request logged for this {isNetwork ? 'network' : 'address'}; the table counts the last 7 days.</p>}
          {unclassified > 0 && <p>{unclassifiedNote(unclassified, info.blocked)}</p>}
        </div>
      )}

      <div className="flex flex-col gap-2">
        <h3 className="px-5 text-sm font-semibold text-ink">Top destinations</h3>
        <DataTable<ClientDomain>
          caption={`Top destinations of ${ip}`}
          columns={DEST_COLUMNS}
          rows={info.top_domains}
          rowKey={(r) => r.destination}
          empty={{ title: 'No destinations recorded', description: 'Destinations appear here once this client sends a request.' }}
        />
      </div>

      <div className="flex flex-col gap-2">
        <h3 className="px-5 text-sm font-semibold text-ink">Recent requests</h3>
        {info.recent.length === 0 ? (
          <p className="px-5 text-sm text-ink-muted">No request recorded.</p>
        ) : (
          <ul>
            {info.recent.map((r, i) => (
              <li key={`${r.timestamp}-${i}`} className="flex flex-col gap-1 border-t border-line-subtle px-5 py-2 text-xs">
                <code className="truncate font-mono text-ink" title={r.destination}>{r.destination}</code>
                <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-ink-muted">
                  <span className="whitespace-nowrap font-mono tabular-nums" title={formatWhenExact(r.timestamp)}>{shortTime(r.timestamp)}</span>
                  <span className="font-mono">{r.method}</span>
                  <RecentReason r={r} />
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function ClientDrawer({ ip, row, onClose }: { ip: string; row?: ClientStat; onClose: () => void }) {
  const modalRef = useModal<HTMLDivElement>(true, onClose);
  const headingId = useId();
  // Rendered into document.body: a position: fixed overlay is laid out
  // against the viewport only when no ancestor has a transform, filter or
  // backdrop-filter. Inside the page the drawer covered the page box, not
  // the window.
  return createPortal(
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true" aria-labelledby={headingId}>
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div ref={modalRef} className="relative h-full w-full max-w-md overflow-y-auto border-l border-line bg-surface text-ink shadow-2xl">
        <div className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-line-subtle bg-surface px-5 py-3">
          <h2 id={headingId} className="truncate font-mono text-base font-semibold">{ip}</h2>
          <IconButton aria-label="Close" icon={<X />} onClick={onClose} />
        </div>
        <div className="pt-4">
          <ClientDetailBody ip={ip} row={row} />
        </div>
      </div>
    </div>,
    document.body,
  );
}
