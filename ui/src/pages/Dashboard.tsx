/**
 * Overview (route "/"): the last 24 hours of client traffic, what blocked
 * it, and the state of the services, from dashboard/summary, logs/timeline,
 * status and cache/statistics. Every number on the page is a field of one of
 * those responses; a field the backend did not send is shown as "Not
 * reported", never as 0.
 *
 * Not here any more: the security score (GET /api/security/score is still
 * served, no page shows it), the WAF requests-per-minute and URL entropy
 * figures, and the Reset counters button, which is in Settings, Admin and backup,
 * behind the same confirmation.
 *
 * There is no time-range control: dashboard/summary has one window per
 * figure (24 hours for these cards, the chart and the top list) and takes no
 * range, so a 1h / 7d switch would change the chart and nothing else.
 */
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { Check, Copy } from 'lucide-react';
import toast from 'react-hot-toast';
import { getData } from '../lib/api';
import { statusQuery } from '../lib/queries';
import { proxyAddress, parseUtc } from '../lib/utils';
import { formatClock, formatCount, formatDate, formatHourMinute, formatShare, formatTime } from '../lib/format';
import type { CacheStats, DashboardSummary, TimelineEntry } from '../types';
import { PageHeader } from '../components/ui/PageHeader';
import { Section } from '../components/ui/Section';
import { StatCard } from '../components/ui/StatCard';
import { Badge } from '../components/ui/Badge';
import { Notice } from '../components/ui/Notice';
import { EmptyState } from '../components/ui/EmptyState';
import { DataTable, type Column } from '../components/ui/DataTable';
import { IconButton } from '../components/ui/Button';
import { RequestsPerHour } from '../components/dashboard/RequestsPerHour';
import { BlockedByRule } from '../components/dashboard/BlockedByRule';
import { ServicesPanel } from '../components/dashboard/ServicesPanel';
import { serviceRows } from '../components/dashboard/services';

const REFETCH = 30_000;

type TopBlocked = DashboardSummary['top_blocked'][number];
type RecentBlock = DashboardSummary['recent_blocks'][number];

function usePageVisible(): boolean {
  const [visible, setVisible] = useState(document.visibilityState !== 'hidden');
  useEffect(() => {
    const h = () => setVisible(document.visibilityState !== 'hidden');
    document.addEventListener('visibilitychange', h);
    return () => document.removeEventListener('visibilitychange', h);
  }, []);
  return visible;
}

function ProxyChip() {
  const proxy = proxyAddress();
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);
  const copy = () => {
    navigator.clipboard.writeText(proxy).then(() => {
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 2000);
    }).catch(() => toast.error('Clipboard access denied'));
  };
  return (
    <div className="flex h-9 max-w-full items-center rounded-control border border-line bg-surface pl-3">
      <span className="pr-2 text-xs text-ink-muted">Proxy</span>
      <code className="min-w-0 truncate font-mono text-[13px] text-ink">{proxy}</code>
      <IconButton aria-label="Copy proxy address" size="sm" icon={copied ? <Check /> : <Copy />} onClick={copy} className="ml-1" />
      <span role="status" className="sr-only">{copied ? 'Proxy address copied' : ''}</span>
    </div>
  );
}

/** The notices the summary's own state calls for, and only those. */
function notices(summary: { data?: DashboardSummary | null; isError: boolean }): ReactNode[] {
  const out: ReactNode[] = [];
  if (summary.isError) {
    out.push(
      <Notice key="summary" tone="danger" title="The overview could not be loaded">
        dashboard/summary did not answer, so the counts, the rules and the latest blocks are missing until it does.
      </Notice>,
    );
  }
  const s = summary.data;
  const acl = s?.squid_domain_acl;
  if (acl && !acl.held) {
    out.push(acl.names > acl.limit ? (
      <Notice
        key="acl"
        tone="warning"
        title="Blacklisted domains are blocked at DNS only"
        action={<Link to="/blacklists" className="underline-offset-2 hover:underline">Open blacklists</Link>}
      >
        {/* One sentence on a phone (Mobile.dc.html), the consequence from sm up. */}
        <span className="sm:hidden">{formatCount(acl.names)} names, above the proxy limit of {formatCount(acl.limit)}.</span>
        <span className="hidden sm:inline">
          The list has {formatCount(acl.names)} names, above the proxy&apos;s limit of {formatCount(acl.limit)} (SPM_SQUID_DOMAIN_ACL_MAX), so
          Squid does not hold its own copy. The DNS sinkhole still blocks every name, but a domain a client reached shortly before it was listed
          stays reachable for up to a minute.
        </span>
      </Notice>
    ) : (
      <Notice key="acl" tone="warning" title="Squid could not load its copy of the domain blacklist">
        The proxy could not write it, so only the DNS sinkhole blocks blacklisted domains. The proxy log says why.
      </Notice>
    ));
  }
  if (s?.waf_status === 'auth_failed') {
    out.push(
      <Notice key="waf" tone="warning" title="The WAF refuses the backend">
        The WAF refused the backend credential, so its statistics and category switches are unavailable. Set INTERNAL_ALERT_TOKEN to the same
        value on the waf and backend services.
      </Notice>,
    );
  }
  return out;
}

/** A recent block's time: HH:MM:SS today, the date as well before today. */
function blockTime(ts: string, now: number): string {
  const d = parseUtc(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const today = new Date(now);
  const sameDay = d.getFullYear() === today.getFullYear() && d.getMonth() === today.getMonth() && d.getDate() === today.getDate();
  return sameDay ? formatTime(ts) : `${formatDate(ts)} ${formatHourMinute(ts)}`;
}

function ReasonBadge({ reason, label }: { reason?: string; label?: string }) {
  if (!label) return <Badge tone="neutral">Rule not reported</Badge>;
  return <Badge tone={reason === 'unclassified' ? 'neutral' : 'danger'}>{label}</Badge>;
}

const TOP_COLUMNS: Column<TopBlocked>[] = [
  {
    id: 'dest',
    header: 'Destination',
    // A host is not broken across lines: a long one is cut with an ellipsis,
    // whole in the tooltip, so the Blocked column stays in view.
    cell: (r) => <code title={r.dest} className="block max-w-[12rem] truncate font-mono text-[13px] 2xl:max-w-[18rem]">{r.dest}</code>,
  },
  {
    id: 'rule',
    header: 'Rule',
    cell: (r) => r.reasons?.length ? (
      <span className="flex flex-wrap gap-1">
        {r.reasons.map((x) => <ReasonBadge key={x.reason} reason={x.reason} label={x.label} />)}
      </span>
    ) : <ReasonBadge />,
  },
  { id: 'count', header: 'Blocked', align: 'right', cell: (r) => <span className="font-medium">{formatCount(r.count)}</span> },
];

function LatestBlocks({ rows, loading, error, now }: { rows?: RecentBlock[]; loading: boolean; error: boolean; now: number }) {
  let body: ReactNode;
  if (loading) {
    body = (
      <div className="px-5 pb-5">
        <span aria-hidden="true" className="block h-24 rounded-md bg-line-subtle animate-pulse" />
        <span role="status" className="sr-only">Loading latest blocks</span>
      </div>
    );
  } else if (error || !rows) {
    body = <p className="px-5 pb-5 text-sm text-ink-muted">Not reported: the dashboard summary did not load.</p>;
  } else if (rows.length === 0) {
    body = <EmptyState title="No blocked requests yet" description="Blocks appear here when a rule stops a client request." />;
  } else {
    body = (
      <ul>
        {rows.map((b, i) => (
          <li key={`${b.timestamp}-${i}`} className="flex flex-col gap-1 border-t border-line-subtle px-5 py-2.5 sm:flex-row sm:items-center sm:gap-3">
            <span className="shrink-0 font-mono text-xs tabular-nums text-ink-muted sm:w-[72px]" title={b.timestamp ? `${formatDate(b.timestamp)} ${formatTime(b.timestamp)}` : undefined}>
              {blockTime(b.timestamp, now)}
            </span>
            <div className="flex min-w-0 flex-1 flex-col gap-0.5">
              <code className="truncate font-mono text-[13px] text-ink" title={b.destination}>{b.host || b.destination}</code>
              <span className="text-xs text-ink-muted">{b.source_ip || 'Client not recorded'}</span>
            </div>
            <span className="shrink-0"><ReasonBadge reason={b.reason} label={b.reason_label} /></span>
          </li>
        ))}
      </ul>
    );
  }
  return (
    <Section title="Latest blocks" flush action={{ label: 'Open access logs', to: '/logs' }} className="flex-[1_1_420px]">
      {body}
    </Section>
  );
}

export function Dashboard() {
  const visible = usePageVisible();
  const refetchInterval = visible ? REFETCH : false;
  const summary = useQuery<DashboardSummary | null>({
    queryKey: ['dashboard'],
    queryFn: () => getData<DashboardSummary>('dashboard/summary'),
    refetchInterval,
  });
  const timeline = useQuery<TimelineEntry[] | null>({
    queryKey: ['timeline'],
    queryFn: () => getData<TimelineEntry[]>('logs/timeline'),
    refetchInterval,
  });
  const status = useQuery({ ...statusQuery, refetchInterval, staleTime: 10_000 });
  const cache = useQuery<CacheStats | null>({
    queryKey: ['cache'],
    queryFn: () => getData<CacheStats>('cache/statistics'),
    refetchInterval,
  });

  const s = summary.data ?? undefined;
  const loading = summary.isPending;
  const requests = s?.last_24h_requests;
  const blocked = s?.last_24h_blocked;
  const clients = s?.last_24h_clients;
  const share = typeof blocked === 'number' && typeof requests === 'number' ? formatShare(blocked, requests) : null;
  const ipRules = s?.ip_blacklist_count;
  const domainRules = s?.domain_blacklist_count;
  const rules = typeof ipRules === 'number' && typeof domainRules === 'number' ? ipRules + domainRules : undefined;
  const lastRequest = s?.last_request_at ? formatHourMinute(s.last_request_at) : null;
  const onlyClient = clients === 1 ? s?.top_clients?.[0]?.ip : undefined;

  let clientsSub: ReactNode;
  if (clients === 0) clientsSub = 'No client in the last 24 hours';
  else if (onlyClient) clientsSub = <><code className="font-mono text-xs">{onlyClient}</code>{lastRequest && `, last request ${lastRequest}`}</>;
  else if (lastRequest) clientsSub = `last request ${lastRequest}`;
  // The stack's own addresses (the Docker host, the backend, loopback) are
  // in no count on this page; say how many were left out.
  const internal = s?.last_24h_internal_sources;
  if (internal) {
    const note = `${formatCount(internal)} internal ${internal === 1 ? 'address' : 'addresses'} not counted`;
    clientsSub = clientsSub ? <span className="flex flex-col gap-0.5"><span>{clientsSub}</span><span>{note}</span></span> : note;
  }

  let blockedSub: ReactNode;
  if (share) {
    blockedSub = (
      <span className="flex items-center gap-2">
        <span aria-hidden="true" className="hidden h-1.5 flex-1 overflow-hidden rounded-full bg-line-subtle sm:block">
          <span className="block h-1.5 bg-danger-strong" style={{ width: share }} />
        </span>
        <span>{share} of requests</span>
      </span>
    );
  } else if (requests === 0) {
    blockedSub = 'No requests to block';
  }

  const updated = summary.dataUpdatedAt ? ` · updated ${formatClock(summary.dataUpdatedAt)}` : '';
  const pageNotices = notices(summary);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Overview" description={`Last 24 hours${updated}`} actions={<ProxyChip />} />

      {pageNotices.length > 0 && <div className="flex flex-col gap-3">{pageNotices}</div>}

      <section aria-label="Last 24 hours at a glance" className="grid grid-cols-2 gap-3 lg:grid-cols-4 lg:gap-4 [&_p]:[overflow-wrap:anywhere]">
        <StatCard
          label="Client requests"
          loading={loading}
          value={requests}
          sub={typeof clients === 'number' && clients > 0 ? `from ${formatCount(clients)} ${clients === 1 ? 'client' : 'clients'}` : undefined}
        />
        <StatCard label="Blocked" tone={blocked ? 'danger' : 'default'} loading={loading} value={blocked} sub={blockedSub} />
        <StatCard label="Active clients" loading={loading} value={clients} sub={clientsSub} />
        <StatCard
          label="Rules in force"
          loading={loading}
          value={rules}
          sub={rules !== undefined ? `${formatCount(ipRules ?? 0)} IPs, ${formatCount(domainRules ?? 0)} domains` : undefined}
        />
      </section>

      <div className="flex flex-wrap gap-4">
        <RequestsPerHour
          entries={timeline.data}
          now={timeline.dataUpdatedAt}
          loading={timeline.isPending}
          error={timeline.isError}
        />
        <BlockedByRule reasons={s?.blocked_by_reason_24h} loading={loading} />
      </div>

      <div className="flex flex-wrap gap-4">
        {/* Not on a phone, as in Mobile.dc.html: the Access logs list every block. */}
        <Section title="Most blocked destinations" flush action={{ label: 'Open analytics', to: '/analytics' }} className="hidden flex-[1_1_420px] sm:block">
          <DataTable
            caption="Most blocked destinations in the last 24 hours"
            columns={TOP_COLUMNS}
            rows={s?.top_blocked ?? []}
            rowKey={(r) => r.dest}
            loading={loading}
            error={summary.isError ? 'dashboard/summary did not answer.' : null}
            onRetry={() => { void summary.refetch(); }}
            empty={{ title: 'No blocked requests in the last 24 hours', description: 'Destinations appear here when a rule blocks a client request.' }}
          />
        </Section>
        <LatestBlocks rows={s?.recent_blocks} loading={loading} error={summary.isError} now={summary.dataUpdatedAt} />
      </div>

      <ServicesPanel rows={serviceRows(status, summary, cache)} />
    </div>
  );
}
