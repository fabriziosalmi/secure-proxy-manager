/**
 * Requests per hour, the last 24 hours, from logs/timeline: one bar per
 * hour, the blocked requests stacked on the allowed ones, on one axis. The
 * hours the backend did not return are drawn as zero (hourlySlots), never
 * interpolated. Screen readers get the same numbers as text.
 */
import { BarChart3 } from 'lucide-react';
import type { TimelineEntry } from '../../types';
import { formatCount, formatHourMinute } from '../../lib/format';
import { cn } from '../../lib/utils';
import { Section } from '../ui/Section';
import { EmptyState } from '../ui/EmptyState';
import { axisMax, axisTicks, describeHours, hourlySlots } from './hourly';

export interface RequestsPerHourProps {
  entries?: TimelineEntry[] | null;
  /** When the entries were fetched, epoch milliseconds: the end of the window. */
  now: number;
  loading?: boolean;
  error?: boolean;
}

function pct(n: number, max: number): string {
  // A non-zero count is at least one pixel tall, so a quiet hour is not drawn as empty.
  return n > 0 ? `max(1px, ${(n / max) * 100}%)` : '0';
}

// Inline elements only: Section puts its description in a paragraph.
function Legend() {
  return (
    <span className="flex gap-4">
      <span className="flex items-center gap-1.5"><span aria-hidden="true" className="h-2.5 w-2.5 rounded-[2px] bg-chart-neutral" />Allowed</span>
      <span className="flex items-center gap-1.5"><span aria-hidden="true" className="h-2.5 w-2.5 rounded-[2px] bg-danger-strong" />Blocked</span>
    </span>
  );
}

export function RequestsPerHour({ entries, now, loading, error }: RequestsPerHourProps) {
  let body;
  if (loading) {
    body = (
      <div className="h-[140px] sm:h-[200px]">
        <span aria-hidden="true" className="block h-full rounded-md bg-line-subtle animate-pulse" />
        <span role="status" className="sr-only">Loading requests per hour</span>
      </div>
    );
  } else if (error || !entries) {
    body = (
      <p role="alert" className="py-10 text-center text-sm text-ink-muted">
        Could not load the hourly timeline (logs/timeline). The chart is missing until the backend answers.
      </p>
    );
  } else {
    const slots = hourlySlots(entries, now);
    const max = axisMax(slots);
    if (max === 0) {
      body = (
        <EmptyState
          icon={<BarChart3 strokeWidth={1.75} />}
          title="No client requests in the last 24 hours"
          description="Requests appear here once a device uses the proxy."
        />
      );
    } else {
      const ticks = axisTicks(max);
      body = (
        <div className="flex gap-2">
          <div aria-hidden="true" className="flex h-[120px] w-9 shrink-0 flex-col justify-between text-right text-[11px] tabular-nums leading-none text-ink-subtle sm:h-[180px]">
            {ticks.map((t) => <span key={t}>{formatCount(t)}</span>)}
          </div>
          <div role="img" aria-label={describeHours(slots)} className="flex min-w-0 flex-1 flex-col">
            <div
              data-testid="hour-bars"
              className="flex h-[120px] items-end gap-[2px] border-b border-line sm:h-[180px] sm:gap-1"
              style={{ backgroundImage: 'linear-gradient(var(--color-line-subtle) 1px, transparent 1px)', backgroundSize: '100% 50%' }}
            >
              {slots.map((s) => (
                <div
                  key={s.time}
                  data-hour={s.time}
                  title={`${formatHourMinute(s.time)}: ${formatCount(s.total)} requests, ${formatCount(s.blocked)} blocked`}
                  className="flex h-full min-w-0 flex-1 flex-col justify-end"
                >
                  <div data-series="blocked" className="rounded-t-[2px] bg-danger-strong" style={{ height: pct(s.blocked, max) }} />
                  <div
                    data-series="allowed"
                    className={cn('bg-chart-neutral', s.blocked === 0 && 'rounded-t-[2px]')}
                    style={{ height: pct(s.total - s.blocked, max) }}
                  />
                </div>
              ))}
            </div>
            <div aria-hidden="true" className="flex h-5 items-end gap-[2px] sm:gap-1">
              {slots.map((s, i) => (
                // A label is wider than its hour: the first one grows to the
                // right, the last to the left, the others both ways, so none
                // runs past the chart. Every 3rd hour, every 12th on a phone.
                <span
                  key={s.time}
                  className={cn(
                    'flex min-w-0 flex-1 text-[11px] tabular-nums text-ink-subtle',
                    i === 0 ? 'justify-start' : i === slots.length - 1 ? 'justify-end' : 'justify-center',
                    i % 12 !== 0 && i !== slots.length - 1 && 'invisible',
                    i % 3 === 0 && 'sm:visible',
                  )}
                >
                  {(i % 3 === 0 || i === slots.length - 1) && <span className="whitespace-nowrap">{formatHourMinute(s.time)}</span>}
                </span>
              ))}
            </div>
          </div>
        </div>
      );
    }
  }

  return (
    <Section title="Requests per hour" description={<Legend />} className="flex-[2_1_560px]">
      {body}
    </Section>
  );
}
