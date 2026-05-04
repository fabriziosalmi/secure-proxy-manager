import { Area, Bar, ComposedChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell, PieChart, Pie } from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { AlertTriangle } from 'lucide-react';
import type { TimelineEntry, DashboardSummary } from '../../types';

const C = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#ec4899'];

const TOOLTIP_STYLE = {
  backgroundColor: 'rgba(15, 23, 42, 0.92)',
  backdropFilter: 'blur(12px)',
  WebkitBackdropFilter: 'blur(12px)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '8px',
  fontSize: '11px',
  boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
  fontVariantNumeric: 'tabular-nums' as const,
};

interface Props {
  chart: TimelineEntry[];
  summary?: DashboardSummary;
}

// Default export so React.lazy() can grab it via the standard chunk-loading
// path. Splitting recharts into its own chunk keeps it out of the initial
// route bundle (~110 KB gzipped) for users who land on /dashboard but never
// scroll to the charts.
export default function DashboardCharts({ chart, summary }: Props) {
  return (
    <div className="grid gap-3 lg:grid-cols-12">
      {/* Traffic chart */}
      <Card className="lg:col-span-5">
        <CardHeader className="p-3 pb-0">
          <CardTitle className="text-sm">Traffic 24h</CardTitle>
        </CardHeader>
        <CardContent className="p-2">
          <div className="h-[180px]">
            <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
              <ComposedChart data={chart} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="cT" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} /><stop offset="95%" stopColor="#3b82f6" stopOpacity={0} /></linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#555" fontSize={9} tickLine={false} axisLine={false} />
                <YAxis yAxisId="left" stroke="#555" fontSize={9} tickLine={false} axisLine={false} />
                <YAxis yAxisId="right" orientation="right" stroke="#ef4444" fontSize={9} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Area yAxisId="left" type="monotone" dataKey="total" name="Total" stroke="#3b82f6" strokeWidth={1.5} fill="url(#cT)" />
                <Bar yAxisId="right" dataKey="blocked" name="Blocked" fill="#ef4444" opacity={0.7} radius={[2, 2, 0, 0]} />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Threat categories pie */}
      <Card className="lg:col-span-3">
        <CardHeader className="p-3 pb-0">
          <CardTitle className="text-sm">Threats</CardTitle>
        </CardHeader>
        <CardContent className="p-2">
          {(summary?.threat_categories?.length ?? 0) > 0 && summary ? (
            <>
              <div className="h-[130px]">
                <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                  <PieChart><Pie data={summary.threat_categories} dataKey="count" nameKey="category" cx="50%" cy="50%" innerRadius={35} outerRadius={55} paddingAngle={3}>
                    {summary.threat_categories.map((_: unknown, i: number) => <Cell key={i} fill={C[i % C.length]} />)}
                  </Pie><Tooltip contentStyle={TOOLTIP_STYLE} /></PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex flex-wrap gap-1 mt-1">{summary.threat_categories.map((c: { category: string; count: number }, i: number) => (
                <span key={c.category} className="text-[10px] px-1.5 py-0.5 rounded-full border" style={{ borderColor: C[i % C.length] + '40', color: C[i % C.length] }}>{c.category} ({c.count})</span>
              ))}</div>
            </>
          ) : <div className="h-[180px] flex items-center justify-center text-muted-foreground text-xs">No threats</div>}
        </CardContent>
      </Card>

      {/* Top blocked */}
      <Card className="lg:col-span-4">
        <CardHeader className="p-3 pb-0">
          <CardTitle className="text-sm flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5 text-destructive" aria-hidden="true" />Top Blocked (24h)</CardTitle>
        </CardHeader>
        <CardContent className="p-2">
          <div className="space-y-1 max-h-[180px] overflow-y-auto custom-scrollbar">
            {summary?.top_blocked?.slice(0, 8).map((item: { dest: string; count: number }, i: number) => (
              <div key={i} className="flex items-center justify-between py-1 text-xs row-hover rounded px-1">
                <span className="truncate max-w-[200px] text-muted-foreground font-mono" title={item.dest}>{item.dest}</span>
                <span className="font-bold text-destructive ml-2 shrink-0">{item.count}</span>
              </div>
            ))}
            {(!summary?.top_blocked?.length) && <div className="text-center py-6 text-muted-foreground text-xs">No blocks in 24h</div>}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
