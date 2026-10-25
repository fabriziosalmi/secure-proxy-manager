/**
 * Access logs: every request the proxy handled, newest first, with the rule
 * that blocked it (Logs.dc.html). Rows come from GET /api/logs, filtered on
 * the server, and from the live feed (/api/ws/logs), which adds a row only
 * when it matches the filters on screen.
 *
 * The filters are in the URL so a link opens the same view; whether the
 * stack's own traffic (the backend, this host, loopback) is shown is the
 * viewer's choice, kept in localStorage. A selected row is detailed below
 * the table on a wide screen and in a drawer below lg.
 */
import { createPortal } from 'react-dom';
import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, X } from 'lucide-react';
import toast from 'react-hot-toast';
import { PageHeader } from '../components/ui/PageHeader';
import { Section } from '../components/ui/Section';
import { DataTable, type Column } from '../components/ui/DataTable';
import { SearchInput } from '../components/ui/SearchInput';
import { SegmentedControl } from '../components/ui/SegmentedControl';
import { Switch } from '../components/ui/Switch';
import { Button, IconButton } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { useConfirm } from '../hooks/useConfirm';
import { useModal } from '../hooks/useModal';
import { useMediaQuery, DESKTOP_QUERY } from '../hooks/useMediaQuery';
import { api, getData, getErrorMessage } from '../lib/api';
import { formatBytes, formatCount, formatDate, formatDateTime, formatTime } from '../lib/format';
import {
  allowableDomain, apiParams, hasFilters, isBlocked, matchesFilters, readFilters, splitStatus, whyText, writeFilters,
  NO_FILTERS, type LogFilters, type Outcome,
} from '../lib/accessLog';
import { cn } from '../lib/utils';
import type { ClientsData, LogEntry, LogsPageData, ReasonCount } from '../types';

/** Where the "Show internal traffic" choice is kept, per viewer. */
export const SHOW_INTERNAL_TRAFFIC_KEY = 'spm.logs.showInternal';

/** Rows per request, for the first page and each "Load older". */
export const PAGE_SIZE = 100;

/** Live rows kept above the fetched pages. */
const LIVE_MAX = 200;

function readShowInternal(): boolean {
  try {
    return window.localStorage.getItem(SHOW_INTERNAL_TRAFFIC_KEY) === 'true';
  } catch {
    return false;
  }
}

function writeShowInternal(on: boolean) {
  try {
    window.localStorage.setItem(SHOW_INTERNAL_TRAFFIC_KEY, on ? 'true' : 'false');
  } catch {
    // Storage blocked (private window, previews): the choice lasts for this visit.
  }
}

interface Row {
  key: string;
  entry: LogEntry;
}

const plural = (n: number, one: string, many: string) => `${formatCount(n)} ${n === 1 ? one : many}`;

/** "12:07:56" for a request today in the viewer's zone, "2026-10-21 12:07:56" otherwise. */
function rowTime(ts: string): string {
  if (!ts) return 'Not recorded';
  const now = new Date();
  const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  return formatDate(ts) === today ? formatTime(ts) : formatDateTime(ts);
}

function RuleBadge({ r }: { r: LogEntry }) {
  if (!isBlocked(r)) return <Badge tone="success">Allowed</Badge>;
  const label = r.reason_label || r.reason || 'Blocked';
  return <Badge tone={r.reason === 'unclassified' || !r.reason ? 'neutral' : 'danger'}>{label}</Badge>;
}

function Result({ r }: { r: LogEntry }) {
  const { squid, code } = splitStatus(r.status);
  return (
    <span className="whitespace-nowrap">
      {code && <span className={cn('font-semibold tabular-nums', isBlocked(r) ? 'text-danger' : 'text-success')}>{code}</span>}{' '}
      <span className="text-xs text-ink-muted">{squid || 'Not recorded'}</span>
    </span>
  );
}

const SELECT_CLASS =
  'h-9 min-w-0 max-w-[14rem] rounded-control border border-line-strong bg-surface px-2.5 text-sm text-ink ' +
  'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent';

type WsStatus = 'connecting' | 'connected' | 'disconnected';

export function Logs() {
  const isDesktop = useMediaQuery(DESKTOP_QUERY);
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => readFilters(params), [params]);
  const [showInternal, setShowInternal] = useState(readShowInternal);
  const [live, setLive] = useState(true);
  const [wsStatus, setWsStatus] = useState<WsStatus>('disconnected');
  const [liveRows, setLiveRows] = useState<Row[]>([]);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [search, setSearch] = useState(filters.q);
  const switchLabelId = useId();
  const { confirm, dialog } = useConfirm();

  const setFilters = (next: Partial<LogFilters>) => {
    setParams(writeFilters({ ...filters, ...next }), { replace: true });
  };

  // The search box writes the URL a moment after typing stops, so each key
  // is not a request. A URL changed from outside (a link, Back) wins.
  const typed = useRef(false);
  useEffect(() => {
    if (typed.current) return;
    setSearch(filters.q);
  }, [filters.q]);
  useEffect(() => {
    if (!typed.current) return;
    const t = setTimeout(() => {
      typed.current = false;
      if (search.trim() !== filters.q) setFilters({ q: search.trim() });
    }, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the typed value restarts the wait
  }, [search]);

  const query = apiParams(filters, showInternal).toString();
  const logs = useInfiniteQuery({
    queryKey: ['logs', 'page', query],
    queryFn: ({ pageParam }) => {
      const p = new URLSearchParams(query);
      p.set('limit', String(PAGE_SIZE));
      p.set('sort', 'id');
      p.set('order', 'desc');
      if (pageParam > 0) p.set('before_id', String(pageParam));
      return api.get(`logs?${p.toString()}`).then((r) => (r.data ?? null) as LogsPageData | null);
    },
    initialPageParam: 0,
    getNextPageParam: (last) => {
      const rows = last?.data ?? [];
      const id = rows[rows.length - 1]?.id;
      return rows.length < PAGE_SIZE || !id ? undefined : id;
    },
  });

  const clients = useQuery<ClientsData | null>({
    queryKey: ['clients', 'statistics'],
    queryFn: () => api.get('clients/statistics').then((r) => r.data ?? null),
  });
  const stats = useQuery<{ blocked_by_reason?: ReasonCount[] } | null>({
    queryKey: ['logs', 'stats'],
    queryFn: () => getData('logs/stats'),
  });

  // The live buffer belongs to the filters it was matched against.
  const liveFor = useRef({ filters, showInternal });
  useEffect(() => {
    liveFor.current = { filters, showInternal };
    // eslint-disable-next-line react-hooks/set-state-in-effect -- a new view starts with no live rows
    setLiveRows([]);
  }, [filters, showInternal]);

  const seq = useRef(0);
  useEffect(() => {
    if (!live) return;

    let ws: WebSocket | null = null;
    let reconnectTimeout: ReturnType<typeof setTimeout> | undefined;
    let cancelled = false;
    let retryCount = 0;
    // True from the moment a connection attempt starts until it ends (the socket
    // closes or the token request fails), so an immediate reconnect never
    // doubles up on one already in progress.
    let attempting = false;
    // The delay doubles from 1 s to this cap and then stays there. There is no
    // attempt limit: a feed that gave up after ten tries (about three minutes)
    // stayed frozen on a tab left open through a backend restart, which is
    // exactly when someone is watching it.
    const MAX_DELAY_MS = 30000;

    const scheduleRetry = () => {
      attempting = false;
      if (cancelled) return;
      const delay = Math.min(1000 * Math.pow(2, retryCount), MAX_DELAY_MS);
      retryCount++;
      setWsStatus('connecting');
      reconnectTimeout = setTimeout(connect, delay);
    };

    const connect = () => {
      if (cancelled) return;
      attempting = true;
      api.get('/ws-token').then(({ data }) => {
        if (cancelled) return;

        const token = data.token;
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const hostname = window.location.hostname;
        const wsPort = (window as Window & { __WS_BACKEND_PORT__?: string }).__WS_BACKEND_PORT__
          ?? import.meta.env.VITE_WS_BACKEND_PORT
          ?? window.location.port
          ?? (window.location.protocol === 'https:' ? '443' : '80');
        const socketUrl = `${wsProtocol}//${hostname}:${wsPort}/api/ws/logs`;

        // Pass the one-time token as a WebSocket subprotocol value instead of a
        // query-string parameter. Query-string tokens leak into server access
        // logs, browser history, and Referer headers; subprotocol values are
        // transmitted only in the WebSocket upgrade headers. "spm.v1" is the
        // one the server selects: a browser fails the handshake when it offers
        // subprotocols and the server selects none.
        ws = new WebSocket(socketUrl, ['spm.v1', `spm-ws-token.${token}`]);
        setWsStatus('connecting');

        ws.onopen = () => {
          setWsStatus('connected');
          retryCount = 0;
          // Keep-alive is server-driven: the backend sends protocol-level
          // WebSocket pings and the browser answers them automatically. No
          // application-level heartbeat is needed from the client.
        };

        ws.onmessage = (event) => {
          try {
            const entry = JSON.parse(event.data);
            // The hub also carries events ({"type": "login_failure", ...}),
            // sent unauthenticated by anyone who fails a login. They used to
            // land here as blank "Invalid Date" rows and push real traffic out
            // of the buffer. Only log rows are kept.
            if (!entry || typeof entry !== 'object' || 'type' in entry) return;
            const row = entry as LogEntry & { client_ip?: string };
            if (!row.source_ip && row.client_ip) row.source_ip = row.client_ip;
            const view = liveFor.current;
            if (!matchesFilters(row, view.filters, view.showInternal)) return;
            seq.current += 1;
            const key = row.id ? `id-${row.id}` : `live-${seq.current}`;
            setLiveRows((prev) => [{ key, entry: row }, ...prev].slice(0, LIVE_MAX));
          } catch { /* skip */ }
        };

        ws.onclose = () => {
          setWsStatus('disconnected');
          scheduleRetry();
        };

        ws.onerror = () => { /* onclose will fire */ };
      }).catch(scheduleRetry);
    };

    // A tab that has been in the background, or a machine that has been offline,
    // should not wait out a 30 s backoff once it can connect again.
    const reconnectNow = () => {
      if (cancelled || attempting) return;
      if (ws && ws.readyState === 1 /* OPEN */) return;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      retryCount = 0;
      connect();
    };
    const onVisible = () => { if (document.visibilityState === 'visible') reconnectNow(); };
    document.addEventListener('visibilitychange', onVisible);
    window.addEventListener('online', reconnectNow);

    connect();

    return () => {
      cancelled = true;
      document.removeEventListener('visibilitychange', onVisible);
      window.removeEventListener('online', reconnectNow);
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        ws.close();
      }
      setWsStatus('disconnected');
    };
  }, [live]);

  const pages = useMemo(() => logs.data?.pages ?? [], [logs.data]);
  const firstMeta = pages[0]?.meta;
  const rows = useMemo<Row[]>(() => {
    const fetched = pages.flatMap((p) => p?.data ?? []).map((e, i) => ({ key: e.id ? `id-${e.id}` : `row-${i}`, entry: e }));
    const seen = new Set(fetched.map((r) => r.key));
    return [...liveRows.filter((r) => !seen.has(r.key)), ...fetched];
  }, [pages, liveRows]);
  const liveAdded = rows.length - pages.reduce((n, p) => n + (p?.data?.length ?? 0), 0);

  const selected = rows.find((r) => r.key === selectedKey)?.entry ?? null;

  const toggleInternal = (on: boolean) => {
    setShowInternal(on);
    writeShowInternal(on);
  };

  const exportCsv = async () => {
    setExporting(true);
    try {
      const res = await api.get(`logs/export?${query}`, { responseType: 'blob' });
      const url = URL.createObjectURL(res.data as Blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `access-log-${new Date().toISOString().slice(0, 10)}.csv`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast.error(getErrorMessage(err, 'The export did not answer.'));
    } finally {
      setExporting(false);
    }
  };

  const allowDomain = async (host: string, r: LogEntry) => {
    const ok = await confirm({
      title: `Allow ${host}?`,
      body:
        `${host} is added to the domain whitelist. That takes this exact name off the domain blacklist, which the proxy ` +
        `and the DNS sinkhole enforce, so "${r.reason_label || r.reason}" no longer blocks it. Other names are not ` +
        'covered, and the other rules (IP blacklist, WAF, egress policy, time and content rules) still apply.',
      confirmLabel: 'Allow domain',
    });
    if (!ok) return;
    try {
      await api.post('domain-whitelist', { domain: host, description: 'Allowed from the access log' });
      toast.success(`${host} is on the domain whitelist. The lists are being exported to the proxy and the DNS sinkhole.`);
      void queryClient.invalidateQueries({ queryKey: ['whitelist', 'domain'] });
    } catch (err) {
      toast.error(getErrorMessage(err, `${host} was not added to the whitelist.`));
    }
  };

  const showClient = (ip: string) => {
    setSelectedKey(null);
    setFilters({ client: ip });
  };

  const clearLogs = async () => {
    const ok = await confirm({
      title: 'Clear the access log?',
      body: 'Every logged request is deleted, for every client, and the statistics built from them start again from zero. This cannot be undone.',
      confirmLabel: 'Clear the log',
      destructive: true,
    });
    if (!ok) return;
    try {
      await api.post('logs/clear');
      toast.success('The access log is empty.');
      setLiveRows([]);
      setSelectedKey(null);
      void queryClient.invalidateQueries({ queryKey: ['logs'] });
    } catch (err) {
      toast.error(getErrorMessage(err, 'The access log was not cleared.'));
    }
  };

  const columns: Column<Row>[] = [
    {
      id: 'time',
      header: 'Time',
      className: 'whitespace-nowrap font-mono text-xs text-ink-muted',
      cell: ({ entry }) => <span title={entry.timestamp ? formatDateTime(entry.timestamp) : undefined}>{rowTime(entry.timestamp)}</span>,
    },
    {
      id: 'client',
      header: 'Client',
      cell: ({ entry }) => (
        <div className="flex min-w-0 flex-col gap-0.5 whitespace-nowrap">
          <code className="font-mono text-xs text-ink">{entry.source_ip || 'Not recorded'}</code>
          {entry.kind && <span className="text-xs text-ink-muted">{entry.kind}</span>}
        </div>
      ),
    },
    {
      id: 'request',
      header: 'Request',
      className: 'w-[40%]',
      cell: (row) => (
        // The destination is cut to the column with its full value on hover.
        // The cap keeps a long URL from widening the table past its box; the
        // floor keeps it readable when the table scrolls on a phone.
        <div className="flex w-[14rem] min-w-0 items-baseline gap-2 sm:w-auto sm:max-w-[16rem] xl:max-w-[21rem] 2xl:max-w-[26rem]">
          <span className="shrink-0 text-[11px] font-semibold text-ink-muted">{row.entry.method || '-'}</span>
          <button
            type="button"
            onClick={() => setSelectedKey(row.key === selectedKey && isDesktop ? null : row.key)}
            aria-pressed={isDesktop ? row.key === selectedKey : undefined}
            aria-haspopup={isDesktop ? undefined : 'dialog'}
            title={row.entry.destination}
            className="min-w-0 truncate rounded-sm text-left font-mono text-[13px] text-ink hover:text-accent hover:underline focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
          >
            {row.entry.destination || 'Not recorded'}
          </button>
        </div>
      ),
    },
    { id: 'result', header: 'Result', cell: ({ entry }) => <Result r={entry} /> },
    { id: 'rule', header: 'Rule', cell: ({ entry }) => <RuleBadge r={entry} /> },
    {
      id: 'size',
      header: 'Size',
      align: 'right',
      className: 'whitespace-nowrap text-ink-muted',
      cell: ({ entry }) => (typeof entry.bytes === 'number' ? formatBytes(entry.bytes) : 'Not recorded'),
    },
  ];

  const hidden = firstMeta?.internal ?? 0;
  const filtered = hasFilters(filters);
  let empty: { title: string; description: ReactNode; action?: ReactNode };
  if (filtered) {
    empty = {
      title: 'No request matches these filters',
      description: hidden > 0 && !showInternal
        ? `${plural(hidden, 'request', 'requests')} from internal sources match and are hidden. Clear the filters, or turn on "Show internal traffic".`
        : 'Clear the filters to see every request.',
      action: <Button size="sm" onClick={() => { setSearch(''); setParams(writeFilters(NO_FILTERS), { replace: true }); }}>Clear filters</Button>,
    };
  } else if (hidden > 0 && !showInternal) {
    empty = {
      title: 'No requests from devices',
      description: `Only internal sources sent requests (${plural(hidden, 'request', 'requests')}, the stack's own traffic). Turn on "Show internal traffic" to see them.`,
    };
  } else {
    empty = {
      title: 'No requests logged yet',
      description: 'Requests appear here once a device uses the proxy.',
    };
  }

  const footer = firstMeta ? footerText(rows.length, firstMeta.total + Math.max(0, liveAdded), filtered, showInternal, filters.client !== '', hidden) : null;

  const clientOptions = useMemo(() => {
    const all = clients.data?.data ?? [];
    const opts = all.filter((c) => showInternal || !c.internal).map((c) => ({
      value: c.ip_address,
      label: c.internal && c.kind ? `${c.ip_address} (${c.kind.replace(/^Internal: /, 'internal: ')})` : c.ip_address,
    }));
    if (filters.client && !opts.some((o) => o.value === filters.client)) opts.unshift({ value: filters.client, label: filters.client });
    return opts;
  }, [clients.data, showInternal, filters.client]);

  const ruleOptions = useMemo(() => {
    const opts = (stats.data?.blocked_by_reason ?? []).map((r) => ({ value: r.reason, label: r.label || r.reason }));
    if (filters.rule && !opts.some((o) => o.value === filters.rule)) opts.unshift({ value: filters.rule, label: filters.rule });
    return opts;
  }, [stats.data, filters.rule]);

  const liveLabel = !live ? 'Paused' : wsStatus === 'connected' ? 'Live' : wsStatus === 'connecting' ? 'Connecting' : 'Reconnecting';

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        eyebrow="Traffic"
        title="Access logs"
        description="Every request the proxy handled, newest first, with the rule that blocked it."
        actions={
          <>
            <Button
              aria-pressed={live}
              onClick={() => setLive((v) => !v)}
              className={cn(live && wsStatus === 'connected' && 'border-success/40 bg-success-subtle text-success hover:enabled:bg-success-subtle hover:enabled:text-success')}
              icon={<span className={cn('block h-2 w-2 rounded-full', live && wsStatus === 'connected' ? 'bg-success' : 'bg-ink-subtle')} />}
            >
              {liveLabel}
            </Button>
            <Button icon={<Download />} onClick={() => { void exportCsv(); }} disabled={exporting}>
              {exporting ? 'Exporting' : 'Export CSV'}
            </Button>
          </>
        }
      />

      <section aria-label="Filters" className="flex flex-wrap items-center gap-3">
        <SearchInput
          label="Search destinations"
          placeholder="Search host or URL"
          value={search}
          onChange={(v) => { typed.current = true; setSearch(v); }}
          className="w-full sm:w-auto sm:flex-[1_1_220px] sm:max-w-[320px]"
        />
        <SegmentedControl<Outcome>
          label="Outcome"
          value={filters.outcome}
          onChange={(outcome) => setFilters({ outcome })}
          options={[{ value: 'all', label: 'All' }, { value: 'allowed', label: 'Allowed' }, { value: 'blocked', label: 'Blocked' }]}
        />
        <label className="flex min-w-0 items-center gap-2 text-sm text-ink-secondary">
          Client
          <select className={SELECT_CLASS} value={filters.client} onChange={(e) => setFilters({ client: e.target.value })}>
            <option value="">All clients</option>
            {clientOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
        <label className="flex min-w-0 items-center gap-2 text-sm text-ink-secondary">
          Rule
          <select className={SELECT_CLASS} value={filters.rule} onChange={(e) => setFilters({ rule: e.target.value })}>
            <option value="">Any rule</option>
            {ruleOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
        <div className="flex h-9 items-center gap-2.5 rounded-control border border-line-strong bg-surface px-3 text-sm text-ink-secondary">
          <Switch labelledBy={switchLabelId} checked={showInternal} onChange={toggleInternal} />
          <span id={switchLabelId}>Show internal traffic</span>
        </div>
      </section>

      <Section title="Requests" flush>
        <DataTable<Row>
          caption="Access log requests"
          columns={columns}
          rows={rows}
          rowKey={(r) => r.key}
          loading={logs.isPending}
          error={logs.isError ? 'logs did not answer.' : null}
          onRetry={() => { void logs.refetch(); }}
          empty={empty}
          isRowSelected={isDesktop ? (r) => r.key === selectedKey : undefined}
        />
        {footer && (
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line-subtle px-5 py-3">
            <p className="text-[13px] text-ink-muted">{footer}</p>
            {logs.hasNextPage && (
              <Button size="sm" onClick={() => { void logs.fetchNextPage(); }} disabled={logs.isFetchingNextPage}>
                {logs.isFetchingNextPage ? 'Loading older' : 'Load older'}
              </Button>
            )}
          </div>
        )}
      </Section>

      {isDesktop && selected && (
        <Section title="Request details">
          <RequestDetail r={selected} filters={filters} onAllow={allowDomain} onShowClient={showClient} />
        </Section>
      )}

      {!isDesktop && selected && (
        <RequestDrawer onClose={() => setSelectedKey(null)}>
          <RequestDetail r={selected} filters={filters} onAllow={allowDomain} onShowClient={showClient} />
        </RequestDrawer>
      )}

      <Section title="Clear the access log" tone="danger" description="Deletes every logged request. The statistics on the Overview and the Clients page are built from them.">
        <Button variant="danger-outline" onClick={() => { void clearLogs(); }}>Clear the log</Button>
      </Section>

      {dialog}
    </div>
  );
}

function footerText(shown: number, total: number, filtered: boolean, showInternal: boolean, namedClient: boolean, hidden: number): string {
  const parts = [`${formatCount(shown)} of ${plural(total, filtered ? 'matching request' : 'request', filtered ? 'matching requests' : 'requests')} shown, newest first.`];
  if (!showInternal && !namedClient) {
    if (hidden > 0) {
      parts.push(`${plural(hidden, 'request', 'requests')} from internal sources (the stack's own traffic) ${hidden === 1 ? 'is' : 'are'} hidden.`);
    } else {
      parts.push(filtered ? 'No internal traffic matches these filters.' : 'No internal traffic was logged.');
    }
  }
  return parts.join(' ');
}

function RequestDetail({ r, filters, onAllow, onShowClient }: {
  r: LogEntry;
  filters: LogFilters;
  onAllow: (host: string, r: LogEntry) => void;
  onShowClient: (ip: string) => void;
}) {
  const host = allowableDomain(r);
  const { squid, code } = splitStatus(r.status);
  return (
    <div className="flex flex-col gap-4">
      <dl className="grid grid-cols-[repeat(auto-fit,minmax(220px,1fr))] gap-x-6 gap-y-3 text-sm">
        <div className="min-w-0">
          <dt className="text-xs text-ink-muted">Destination</dt>
          <dd className="mt-0.5"><code className="break-all font-mono text-[13px]">{r.destination || 'Not recorded'}</code></dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-ink-muted">Client</dt>
          <dd className="mt-0.5">
            <code className="font-mono text-[13px]">{r.source_ip || 'Not recorded'}</code>
            {r.kind && <span className="block text-xs text-ink-muted">{r.kind}</span>}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-ink-muted">Time</dt>
          <dd className="mt-0.5 font-mono text-[13px]">{r.timestamp ? formatDateTime(r.timestamp) : 'Not recorded'}</dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-ink-muted">Squid result</dt>
          <dd className="mt-0.5 font-mono text-[13px]">{r.status ? `${squid}${code ? `/${code}` : ''}` : 'Not recorded'} <span className="font-sans text-ink-muted">{r.method}</span></dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-ink-muted">Rule</dt>
          <dd className="mt-0.5"><RuleBadge r={r} /></dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-ink-muted">Why</dt>
          <dd className="mt-0.5">{whyText(r)}</dd>
        </div>
      </dl>
      <div className="flex flex-wrap gap-2">
        {host && <Button size="sm" onClick={() => onAllow(host, r)}>Allow this domain</Button>}
        {r.source_ip && filters.client !== r.source_ip && (
          <Button size="sm" onClick={() => onShowClient(r.source_ip)}>Show this client's requests</Button>
        )}
      </div>
    </div>
  );
}

function RequestDrawer({ onClose, children }: { onClose: () => void; children: ReactNode }) {
  const modalRef = useModal<HTMLDivElement>(true, onClose);
  const headingId = useId();
  // Rendered into document.body, as the Clients drawer: a position: fixed
  // overlay is laid out against the viewport only when no ancestor has a
  // transform, filter or backdrop-filter.
  return createPortal(
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true" aria-labelledby={headingId}>
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div ref={modalRef} className="relative h-full w-full max-w-md overflow-y-auto border-l border-line bg-surface text-ink shadow-2xl">
        <div className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-line-subtle bg-surface px-5 py-3">
          <h2 id={headingId} className="text-base font-semibold">Request details</h2>
          <IconButton aria-label="Close" icon={<X />} onClick={onClose} />
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>,
    document.body,
  );
}
