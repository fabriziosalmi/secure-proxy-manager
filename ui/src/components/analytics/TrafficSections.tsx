/**
 * The four smaller Analytics sections. Each says what it counts and over
 * which window, and every number is a field of its endpoint:
 *
 * - WAF rule matches: the WAF's own counters, since it last started or its
 *   counters were reset (waf/stats, or waf_status saying why not). A match is
 *   not a block: the WAF counts every category that matched a request,
 *   including matches too weak to block it;
 * - Cloud services in use: client requests of the last 7 days to known
 *   services, by host (analytics/shadow-it);
 * - Traffic by kind of service: client requests of the last 7 days by the
 *   kind the host name suggests (analytics/user-agents, service_types);
 * - Downloads by file type: client requests of the last 7 days whose URL
 *   path ends in a file extension (analytics/file-extensions).
 *
 * "Client" means what the rest of the UI means: no DNS sinkhole rows and no
 * requests from the stack's own addresses.
 */
import type { ReactNode } from 'react';
import type { FileExtData, ServiceTypeData, ShadowItService, WafStatus } from '../../types';
import type { WafReading } from '../../lib/wafStats';
import { formatCount } from '../../lib/format';
import { wafCategoryLabel } from '../../lib/wafCategories';
import { Section } from '../ui/Section';
import { DataTable, type Column } from '../ui/DataTable';

interface QueryState<T> {
  data?: T | null;
  loading: boolean;
  error: boolean;
}

function Loading({ what }: { what: string }) {
  return (
    <div>
      <span aria-hidden="true" className="block h-24 rounded-md bg-line-subtle animate-pulse" />
      <span role="status" className="sr-only">Loading {what}</span>
    </div>
  );
}

function Missing({ children }: { children: ReactNode }) {
  return <p role="alert" className="text-sm text-ink-muted">{children}</p>;
}

/** Name and count rows with a bar each, scaled to the largest; the bar repeats the number. */
function CountBars({ rows, label }: { rows: { name: string; count: number; detail?: string }[]; label: string }) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <ul aria-label={label} className="flex flex-col gap-2.5">
      {rows.map((r) => (
        <li key={r.name} className="flex flex-col gap-1">
          <div className="flex items-baseline justify-between gap-3 text-sm">
            <span className="min-w-0 text-ink [overflow-wrap:anywhere]">
              {r.name}
              {r.detail && <span className="ml-2 text-xs text-ink-muted">{r.detail}</span>}
            </span>
            <span className="font-semibold tabular-nums text-ink">{formatCount(r.count)}</span>
          </div>
          <div aria-hidden="true" className="h-1.5 overflow-hidden rounded-full bg-line-subtle">
            <div className="h-1.5 rounded-full bg-chart-neutral" style={{ width: `${(r.count / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

const GRID_ITEM = 'min-w-0';

// ── WAF rule matches ────────────────────────────────────────────────────────

function wafMissing(status: WafStatus): string {
  switch (status) {
    case 'auth_failed':
      return 'Not available: the WAF refuses the backend credential. Set INTERNAL_ALERT_TOKEN to the same value on the waf and backend services.';
    case 'error':
      return 'Not available: the WAF answered the backend with an error.';
    case 'unreachable':
      return 'Not available: the WAF did not answer the backend.';
    default:
      return 'Not available: the backend sent no WAF statistics.';
  }
}

export function WafCategories({ reading }: { reading: QueryState<WafReading> }) {
  const s = reading.data;
  const waf = s?.waf;
  let description: ReactNode = 'Requests that matched a rule in each category, as the WAF counts them. A match is not a block.';
  let body: ReactNode;
  if (reading.loading) {
    body = <Loading what="WAF rule matches" />;
  } else if (reading.error || !s) {
    body = <Missing>Not reported: waf/stats did not answer.</Missing>;
  } else if (!waf || s.waf_status !== 'ok') {
    body = <Missing>{wafMissing(s.waf_status)}</Missing>;
  } else {
    const cats = waf.top_blocked_categories ?? [];
    const inspected = `${formatCount(waf.total_requests)} ${waf.total_requests === 1 ? 'request' : 'requests'}`;
    description = `Since the WAF started or its counters were reset: ${inspected} inspected, ${formatCount(waf.total_blocked)} blocked. A match is not a block: a request is blocked only when its matches add up to the block threshold.`;
    body = cats.length === 0 ? (
      <p className="text-sm text-ink-muted">No category matched a request.</p>
    ) : (
      <div className="flex flex-col gap-3">
        <CountBars
          label="Requests that matched each WAF category"
          rows={cats.map((c) => {
            const { label, kind } = wafCategoryLabel(c.key);
            return { name: label, count: c.count, detail: kind };
          })}
        />
        <p className="text-[13px] text-ink-muted">
          {cats.length >= 10 ? 'The WAF reports its 10 most matched categories.' : 'No other category matched.'}
        </p>
      </div>
    );
  }
  return <Section title="WAF rule matches" description={description} className={GRID_ITEM}>{body}</Section>;
}

// ── Cloud services in use ───────────────────────────────────────────────────

const SERVICE_COLUMNS: Column<ShadowItService>[] = [
  { id: 'name', header: 'Service', cell: (r) => <span className="text-ink">{r.name}</span> },
  { id: 'type', header: 'Type', cell: (r) => <span className="text-ink-muted">{r.category}</span> },
  { id: 'requests', header: 'Requests', align: 'right', cell: (r) => <span className="font-medium">{formatCount(r.requests)}</span> },
];

export function ServicesInUse({ services, onRetry }: { services: QueryState<ShadowItService[]>; onRetry: () => void }) {
  return (
    <Section
      title="Cloud services in use"
      description="Client requests in the last 7 days to services recognised by their host name."
      flush
      className={GRID_ITEM}
    >
      <DataTable
        caption="Cloud services in use in the last 7 days"
        columns={SERVICE_COLUMNS}
        rows={services.data ?? []}
        rowKey={(r) => r.name}
        loading={services.loading}
        error={services.error ? 'analytics/shadow-it did not answer.' : null}
        onRetry={onRetry}
        stickyHeader
        maxHeight="320px"
        empty={{
          title: 'No known service in the last 7 days',
          description: 'Services are recognised from a fixed list of host names: file sharing, messaging, AI, social and others.',
        }}
      />
    </Section>
  );
}

// ── Traffic by kind of service ──────────────────────────────────────────────

export function ServiceKinds({ kinds }: { kinds: QueryState<ServiceTypeData> }) {
  let body: ReactNode;
  if (kinds.loading) body = <Loading what="traffic by kind of service" />;
  else if (kinds.error || !kinds.data) body = <Missing>Not reported: analytics/user-agents did not answer.</Missing>;
  else if ((kinds.data.service_types ?? []).length === 0) body = <p className="text-sm text-ink-muted">No client requests in the last 7 days.</p>;
  else body = <CountBars label="Client requests by kind of service" rows={kinds.data.service_types} />;
  return (
    <Section
      title="Traffic by kind of service"
      description="Client requests in the last 7 days, grouped by words in the host name (cdn, update, google.com). Other is every host that matches none."
      className={GRID_ITEM}
    >
      {body}
    </Section>
  );
}

// ── Downloads by file type ──────────────────────────────────────────────────

export function FileTypes({ files }: { files: QueryState<FileExtData> }) {
  let body: ReactNode;
  const d = files.data;
  if (files.loading) {
    body = <Loading what="downloads by file type" />;
  } else if (files.error || !d) {
    body = <Missing>Not reported: analytics/file-extensions did not answer.</Missing>;
  } else {
    // A backend before the empty-list fix sent null for a window with no file
    // request; that is no file request, not a crash.
    const categories = d.categories ?? [];
    const extensions = d.extensions ?? [];
    const total = categories.reduce((n, c) => n + c.count, 0);
    const capped = typeof d.examined === 'number' && typeof d.limit === 'number' && d.examined >= d.limit;
    const capNote = capped ? ` Counted in the newest ${formatCount(d.limit as number)} requests with a URL of the window.` : '';
    if (total === 0) {
      body = <p className="text-sm text-ink-muted">No request for a file in the last 7 days.{capNote}</p>;
    } else {
      const onlyOther = categories.length === 1 && categories[0].category === 'Other';
      body = (
        <div className="flex flex-col gap-3">
          <p className="text-sm text-ink">
            {formatCount(total)} {total === 1 ? 'download' : 'downloads'}
            {onlyOther ? ', all in the Other group: no recognised file type.' : '.'}
          </p>
          {!onlyOther && <CountBars label="Downloads by file type" rows={categories.map((c) => ({ name: c.category, count: c.count }))} />}
          <p className="text-[13px] text-ink-muted [overflow-wrap:anywhere]">
            Extensions: {extensions.slice(0, 8).map((e) => `${e.ext} ${formatCount(e.count)}`).join(', ')}
            {extensions.length > 8 && `, and ${formatCount(extensions.length - 8)} more`}.{capNote}
          </p>
        </div>
      );
    }
  }
  return (
    <Section
      title="Downloads by file type"
      description="Client requests in the last 7 days whose URL ends in a file name. HTTPS that is not inspected shows no URL to the proxy and is not counted."
      className={GRID_ITEM}
    >
      {body}
    </Section>
  );
}
