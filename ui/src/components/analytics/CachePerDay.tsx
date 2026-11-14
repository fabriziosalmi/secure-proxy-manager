/**
 * What the cache did, per day: one bar per calendar day of the viewer's zone,
 * today and the 6 days before, stacked by what the proxy's cache did with the
 * client requests (GET /api/analytics/cache-by-day), in requests or in bytes
 * sent. Above the chart, the week in one sentence: the share of the cacheable
 * requests that came from the cache, and the share of HTTPS tunnels, which no
 * cache can store. The numbers are counted from the access log, so a restart
 * of the proxy does not empty them. Screen readers get the same numbers as
 * text, and the table under the chart lists every day and every outcome.
 */
import { useState } from 'react';
import { DatabaseZap } from 'lucide-react';
import type { CacheByDay, CacheDay } from '../../types';
import { cn } from '../../lib/utils';
import { formatCount } from '../../lib/format';
import { Section } from '../ui/Section';
import { EmptyState } from '../ui/EmptyState';
import { DataTable, type Column } from '../ui/DataTable';
import { SegmentedControl } from '../ui/SegmentedControl';
import { axisTicks } from '../dashboard/hourly';
import { SERIES_BG, barHeight, dayLabel, dayName } from './days';
import {
  type CacheGroup, type CacheMeasure, cacheAxisMax, cacheGroups, cacheSegments, cacheSummary, dayTotal, describeCacheDays,
  formatMeasure,
} from './cache';

export interface CachePerDayProps {
  data?: CacheByDay | null;
  loading?: boolean;
  error?: boolean;
}

const MEASURES = [
  { value: 'requests', label: 'Requests' },
  { value: 'bytes', label: 'Bytes' },
] as const;

// Inline elements only: Section puts its description in a paragraph.
function Legend({ groups }: { groups: CacheGroup[] }) {
  return (
    <span className="flex flex-wrap gap-x-4 gap-y-1">
      {groups.map((g) => (
        <span key={g.key} className="flex items-center gap-1.5">
          <span aria-hidden="true" className={cn('h-2.5 w-2.5 shrink-0 rounded-[2px]', SERIES_BG[g.color])} />
          {g.label}
        </span>
      ))}
    </span>
  );
}

function columns(data: CacheByDay, measure: CacheMeasure): Column<CacheDay>[] {
  const label = new Map(data.outcomes.map((o) => [o.outcome, o.label]));
  return [
    { id: 'day', header: 'Day', cell: (d) => <span className="whitespace-nowrap">{dayName(d.date)} <span className="text-ink-muted">{d.date}</span></span> },
    ...data.outcomes.map((o): Column<CacheDay> => ({
      id: o.outcome,
      header: label.get(o.outcome) ?? o.outcome,
      align: 'right',
      cell: (d) => formatMeasure(d[measure][o.outcome], measure),
    })),
    { id: 'total', header: 'All', align: 'right', cell: (d) => <span className="font-medium">{formatMeasure(dayTotal(d, measure), measure)}</span> },
  ];
}

function Chart({ data, measure }: { data: CacheByDay; measure: CacheMeasure }) {
  const groups = cacheGroups(data);
  const max = cacheAxisMax(data.days, measure);
  const ticks = axisTicks(max);
  const last = data.days[data.days.length - 1]?.date;
  return (
    <div className="flex gap-2">
      <div aria-hidden="true" className="flex h-[160px] w-14 shrink-0 flex-col justify-between text-right text-[11px] leading-none tabular-nums text-ink-subtle sm:h-[200px]">
        {ticks.map((t) => <span key={t}>{formatMeasure(t, measure)}</span>)}
      </div>
      <div className="flex min-w-0 flex-1 flex-col">
        <div
          role="img"
          aria-label={describeCacheDays(data, measure)}
          data-testid="cache-bars"
          className="flex h-[160px] items-end gap-2 border-b border-line sm:h-[200px] sm:gap-3"
          style={{ backgroundImage: 'linear-gradient(var(--color-line-subtle) 1px, transparent 1px)', backgroundSize: '100% 50%' }}
        >
          {data.days.map((d) => {
            const total = dayTotal(d, measure);
            const segments = cacheSegments(d, groups, measure).filter((s) => s.value > 0);
            return (
              <div
                key={d.date}
                data-day={d.date}
                title={`${dayName(d.date)}: ${total > 0 ? segments.map((s) => `${formatMeasure(s.value, measure)} ${s.group.label}`).join(', ') : 'no requests'}`}
                className="flex h-full min-w-0 flex-1 flex-col justify-end"
              >
                <div data-testid="cache-bar" className="flex min-h-0 flex-col-reverse overflow-hidden rounded-t-[3px]" style={{ height: barHeight(total, max) }}>
                  {segments.map((s, i) => (
                    <div
                      key={s.group.key}
                      data-group={s.group.key}
                      data-value={s.value}
                      className={cn('min-h-0 basis-0', SERIES_BG[s.group.color], i < segments.length - 1 && 'border-t-2 border-surface')}
                      style={{ flexGrow: s.value }}
                    />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
        <div aria-hidden="true" className="flex gap-2 pt-1.5 sm:gap-3">
          {data.days.map((d) => {
            const { weekday, day } = dayLabel(d.date);
            return (
              <span
                key={d.date}
                className={cn('flex min-w-0 flex-1 flex-col items-center text-[11px] leading-4 tabular-nums sm:flex-row sm:justify-center sm:gap-1 sm:text-xs', d.date === last ? 'font-semibold text-ink' : 'text-ink-muted')}
              >
                <span>{weekday}</span>
                <span>{day}</span>
              </span>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/** The week in one or two sentences, every figure from the totals. */
function Summary({ data }: { data: CacheByDay }) {
  const s = cacheSummary(data);
  return (
    <p data-testid="cache-summary" className="text-sm leading-6 text-ink">
      {s.share === null
        ? 'No request the cache could have answered in these 7 days.'
        : `The cache answered ${s.share} of the ${formatCount(s.cacheable)} requests it could have answered (${s.byteShare ?? '0.0%'} of their bytes)${s.revalidated > 0 ? `, ${formatCount(s.revalidated)} of them after checking with the server` : ''}.`}
      {s.tunnelShare !== null && data.totals.requests.tunnel > 0 && (
        ` ${s.tunnelShare} of the requests (${s.tunnelByteShare ?? '0.0%'} of the bytes) were HTTPS tunnels: the proxy relays them without reading them, so no cache can store them unless HTTPS inspection is on.`
      )}
    </p>
  );
}

export function CachePerDay({ data, loading, error }: CachePerDayProps) {
  const [measure, setMeasure] = useState<CacheMeasure>('requests');
  let body;
  let groups: CacheGroup[] = [];
  if (loading) {
    body = (
      <div className="h-[180px] sm:h-[220px]">
        <span aria-hidden="true" className="block h-full rounded-md bg-line-subtle animate-pulse" />
        <span role="status" className="sr-only">Loading what the cache did per day</span>
      </div>
    );
  } else if (error || !data) {
    body = (
      <p role="alert" className="py-10 text-center text-sm text-ink-muted">
        Could not load the daily counts (analytics/cache-by-day). The chart is missing until the backend answers.
      </p>
    );
  } else {
    groups = cacheGroups(data);
    const total = data.days.reduce((n, d) => n + dayTotal(d, 'requests'), 0);
    const internal = data.internal_sources;
    const note = (
      <p className="text-[13px] leading-5 text-ink-muted">
        Today and the 6 days before, midnight to midnight in your time zone ({data.tz}), counted from the access log: bytes are what the
        proxy sent to the clients.
        {internal > 0 && ` Requests from ${formatCount(internal)} internal ${internal === 1 ? 'address' : 'addresses'} in these 7 days are not counted.`}
      </p>
    );
    body = total === 0 ? (
      <div className="flex flex-col gap-3">
        <EmptyState
          icon={<DatabaseZap strokeWidth={1.75} />}
          title="No client requests in the last 7 days"
          description="The proxy logged no client request on any of these days."
        />
        {note}
      </div>
    ) : (
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <Summary data={data} />
          <SegmentedControl label="Measure" options={MEASURES} value={measure} onChange={setMeasure} size="sm" />
        </div>
        <Chart data={data} measure={measure} />
        {note}
        <details className="group">
          <summary className="cursor-pointer rounded-sm text-sm font-semibold text-accent focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent">
            Show the numbers
          </summary>
          <DataTable
            caption={`What the cache did on each of the last 7 days, ${measure === 'bytes' ? 'bytes sent' : 'requests'}`}
            columns={columns(data, measure)}
            rows={data.days}
            rowKey={(d) => d.date}
            empty={{ title: 'No days', description: 'The backend returned no days.' }}
            className="-mx-5 mt-3"
          />
        </details>
      </div>
    );
  }
  return (
    <Section
      title="What the cache did, per day"
      description={groups.length > 0 ? <Legend groups={groups} /> : undefined}
    >
      {body}
    </Section>
  );
}
