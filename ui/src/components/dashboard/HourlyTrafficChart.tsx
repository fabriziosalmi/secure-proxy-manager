import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { TimelineEntry } from '../../types';
import { useReducedMotion } from '../../hooks/useReducedMotion';
import { TOOLTIP_STYLE } from '../../lib/chart';

const TOTAL_COLOR = '#3b82f6';
const BLOCKED_COLOR = '#ef4444';

// One bar per hour, because that is what logs/timeline returns: a count per
// hour bucket. A monotone area through three points drew a smooth bell, with
// values between the hours that were never measured. Blocked is a subset of
// Total, so it is drawn over the Total bar of the same hour (its own hidden
// x axis puts it at the same position) on the same y axis, and the red share
// of each bar is the blocked share of that hour.
export function HourlyTrafficChart({ data }: { data: TimelineEntry[] }) {
  const reducedMotion = useReducedMotion();
  return (
    <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
      <BarChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
        <XAxis xAxisId="hour" dataKey="time" stroke="hsl(var(--muted-foreground))" fontSize={9} tickLine={false} axisLine={false} />
        <XAxis xAxisId="overlay" dataKey="time" hide />
        <YAxis allowDecimals={false} stroke="hsl(var(--muted-foreground))" fontSize={9} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'hsl(var(--muted-foreground) / 0.08)' }} />
        <Bar xAxisId="hour" dataKey="total" name="Total" fill={TOTAL_COLOR} fillOpacity={0.35} radius={[2, 2, 0, 0]} isAnimationActive={!reducedMotion} />
        <Bar xAxisId="overlay" dataKey="blocked" name="Blocked" fill={BLOCKED_COLOR} fillOpacity={0.85} radius={[2, 2, 0, 0]} isAnimationActive={!reducedMotion} />
      </BarChart>
    </ResponsiveContainer>
  );
}

/** The two-entry key shown next to an hourly chart's title. */
export function HourlyTrafficLegend() {
  return (
    <span className="flex items-center gap-3 text-[10px] font-normal text-muted-foreground">
      <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-xs" style={{ backgroundColor: TOTAL_COLOR, opacity: 0.6 }} />Total</span>
      <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-xs" style={{ backgroundColor: BLOCKED_COLOR }} />Blocked</span>
    </span>
  );
}
