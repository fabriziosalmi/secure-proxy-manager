/**
 * Blocked requests per day, by rule: one bar per calendar day of the
 * viewer's zone, today and the 6 days before, stacked by the rule that
 * blocked the requests (GET /api/analytics/blocked-by-day). Every day the
 * backend returns is drawn, a day without blocks as an empty column on the
 * axis; each rule keeps one colour (seriesFor), named by the API's label in
 * the legend. Screen readers get the same numbers as text, and the table
 * under the chart lists every day and every rule.
 */
import { ShieldCheck } from 'lucide-react';
import type { BlockedByDay, BlockedDay } from '../../types';
import { formatCount } from '../../lib/format';
import { cn } from '../../lib/utils';
import { Section } from '../ui/Section';
import { EmptyState } from '../ui/EmptyState';
import { DataTable, type Column } from '../ui/DataTable';
import { axisMax, axisTicks } from '../dashboard/hourly';
import { SERIES_BG, barHeight, daySegments, dayLabel, dayName, describeDays, reasonsText, seriesFor, type Series } from './days';

export interface BlockedPerDayProps {
  data?: BlockedByDay | null;
  loading?: boolean;
  error?: boolean;
}

// Inline elements only: Section puts its description in a paragraph.
function Legend({ series }: { series: Series[] }) {
  return (
    <span className="flex flex-wrap gap-x-4 gap-y-1">
      {series.map((s) => (
        <span key={s.key} className="flex items-center gap-1.5">
          <span aria-hidden="true" className={cn('h-2.5 w-2.5 shrink-0 rounded-[2px]', SERIES_BG[s.color])} />
          {s.labels.length > 1 ? `${s.label} (${s.labels.join(', ')})` : s.label}
        </span>
      ))}
    </span>
  );
}

const COLUMNS: Column<BlockedDay>[] = [
  { id: 'day', header: 'Day', cell: (d) => <span className="whitespace-nowrap">{dayName(d.date)} <span className="text-ink-muted">{d.date}</span></span> },
  { id: 'rules', header: 'By rule', cell: (d) => (d.blocked > 0 ? reasonsText(d.reasons) : <span className="text-ink-muted">None</span>) },
  { id: 'blocked', header: 'Blocked', align: 'right', cell: (d) => <span className="font-medium">{formatCount(d.blocked)}</span> },
];

function Chart({ data }: { data: BlockedByDay }) {
  const series = seriesFor(data.reasons);
  const max = axisMax(data.days.map((d) => ({ time: d.date, total: d.blocked, blocked: 0 })));
  const ticks = axisTicks(max);
  const last = data.days[data.days.length - 1]?.date;
  return (
    <div className="flex gap-2">
      <div aria-hidden="true" className="flex h-[160px] w-9 shrink-0 flex-col justify-between text-right text-[11px] leading-none tabular-nums text-ink-subtle sm:h-[200px]">
        {ticks.map((t) => <span key={t}>{formatCount(t)}</span>)}
      </div>
      <div className="flex min-w-0 flex-1 flex-col">
        <div
          role="img"
          aria-label={describeDays(data.days)}
          data-testid="day-bars"
          className="flex h-[160px] items-end gap-2 border-b border-line sm:h-[200px] sm:gap-3"
          style={{ backgroundImage: 'linear-gradient(var(--color-line-subtle) 1px, transparent 1px)', backgroundSize: '100% 50%' }}
        >
          {data.days.map((d) => {
            const segments = daySegments(d, series).filter((s) => s.count > 0);
            return (
              <div
                key={d.date}
                data-day={d.date}
                title={`${dayName(d.date)}: ${d.blocked > 0 ? `${formatCount(d.blocked)} blocked (${reasonsText(d.reasons)})` : 'none blocked'}`}
                className="flex h-full min-w-0 flex-1 flex-col justify-end"
              >
                <div data-testid="day-bar" className="flex min-h-0 flex-col-reverse overflow-hidden rounded-t-[3px]" style={{ height: barHeight(d.blocked, max) }}>
                  {segments.map((s, i) => (
                    <div
                      key={s.series.key}
                      data-series={s.series.key}
                      data-count={s.count}
                      className={cn(
                        'min-h-0 basis-0',
                        SERIES_BG[s.series.color],
                        // A 2px surface line between stacked rules, so two
                        // neighbours read as two even where they are close.
                        i < segments.length - 1 && 'border-t-2 border-surface',
                      )}
                      style={{ flexGrow: s.count }}
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

export function BlockedPerDay({ data, loading, error }: BlockedPerDayProps) {
  let body;
  let series: Series[] = [];
  if (loading) {
    body = (
      <div className="h-[180px] sm:h-[220px]">
        <span aria-hidden="true" className="block h-full rounded-md bg-line-subtle animate-pulse" />
        <span role="status" className="sr-only">Loading blocked requests per day</span>
      </div>
    );
  } else if (error || !data) {
    body = (
      <p role="alert" className="py-10 text-center text-sm text-ink-muted">
        Could not load the daily counts (analytics/blocked-by-day). The chart is missing until the backend answers.
      </p>
    );
  } else {
    series = seriesFor(data.reasons);
    const total = data.days.reduce((n, d) => n + d.blocked, 0);
    const internal = data.internal_sources;
    const note = (
      <p className="text-[13px] leading-5 text-ink-muted">
        Today and the 6 days before, midnight to midnight in your time zone ({data.tz}).
        {total > 0 && ` ${formatCount(total)} blocked in all.`}
        {internal > 0 && ` Requests from ${formatCount(internal)} internal ${internal === 1 ? 'address' : 'addresses'} in these 7 days are not counted.`}
      </p>
    );
    body = total === 0 ? (
      <div className="flex flex-col gap-3">
        <EmptyState
          icon={<ShieldCheck strokeWidth={1.75} />}
          title="No blocked requests in the last 7 days"
          description="No rule blocked a client request on any of these days."
        />
        {note}
      </div>
    ) : (
      <div className="flex flex-col gap-4">
        <Chart data={data} />
        {note}
        <details className="group">
          <summary className="cursor-pointer rounded-sm text-sm font-semibold text-accent focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent">
            Show the numbers
          </summary>
          <DataTable
            caption="Blocked requests on each of the last 7 days"
            columns={COLUMNS}
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
      title="Blocked requests per day, by rule"
      description={series.length > 0 ? <Legend series={series} /> : undefined}
      className="flex-[2_1_560px]"
    >
      {body}
    </Section>
  );
}
