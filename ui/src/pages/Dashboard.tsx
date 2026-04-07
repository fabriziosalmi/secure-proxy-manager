import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Zap, Download, Copy, Check, Brain, AlertTriangle, RotateCcw } from 'lucide-react';
import { Area, Bar, ComposedChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell, PieChart, Pie } from 'recharts';
import React, { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { api } from '../lib/api';
import { useAnimatedNumber } from '../hooks/useAnimatedNumber';
import type { TimelineEntry, SecurityScore, DashboardSummary, CacheStats } from '../types';

const REFETCH = 10_000;
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

export function Dashboard() {
  const queryClient = useQueryClient();
  const [copied, setCopied] = useState(false);
  const proxy = `${window.location.hostname}:3128`;
  const copy = () => { navigator.clipboard.writeText(proxy).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); }).catch(() => toast.error('Clipboard access denied')); };

  const [vis, setVis] = useState(document.visibilityState !== 'hidden');
  useEffect(() => { const h = () => setVis(document.visibilityState !== 'hidden'); document.addEventListener('visibilitychange', h); return () => document.removeEventListener('visibilitychange', h); }, []);

  const { data: s, isLoading } = useQuery<DashboardSummary>({ queryKey: ['dashboard'], queryFn: () => api.get('dashboard/summary').then(r => r.data.data), refetchInterval: vis ? REFETCH : false });
  const { data: tl } = useQuery<TimelineEntry[]>({ queryKey: ['timeline'], queryFn: () => api.get('logs/timeline').then(r => r.data.data), refetchInterval: vis ? REFETCH : false });
  const { data: sec } = useQuery<SecurityScore>({ queryKey: ['score'], queryFn: () => api.get('security/score').then(r => r.data.data), refetchInterval: vis ? 30_000 : false });
  const { data: cache } = useQuery<CacheStats>({ queryKey: ['cache'], queryFn: () => api.get('cache/statistics').then(r => r.data.data), refetchInterval: vis ? 30_000 : false });

  const chart = React.useMemo(() => tl ?? [], [tl]);
  const rate = s?.total_requests ? ((s.blocked_requests / s.total_requests) * 100).toFixed(1) : '0';
  const w = s?.waf;

  // Animated numbers
  const animToday = useAnimatedNumber(s?.today_requests ?? 0);
  const animTotal = useAnimatedNumber(s?.total_requests ?? 0);
  const animBlocked = useAnimatedNumber(s?.blocked_requests ?? 0);
  const animScore = useAnimatedNumber(sec?.score ?? 0);
  const animIpRules = useAnimatedNumber(s?.ip_blacklist_count ?? 0);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex justify-between items-center">
          <h1 className="text-2xl font-extrabold tracking-tight bg-gradient-to-b from-white to-white/70 bg-clip-text text-transparent">Dashboard</h1>
        </div>
        <div className="grid gap-3 grid-cols-2 lg:grid-cols-6">
          {Array.from({ length: 6 }).map((_, i) => (
            <Card key={i}><CardContent className="p-3"><div className="h-12 skeleton-shimmer rounded" /></CardContent></Card>
          ))}
        </div>
        <div className="grid gap-3 lg:grid-cols-12">
          <Card className="lg:col-span-7"><CardContent className="p-3"><div className="h-[180px] skeleton-shimmer rounded" /></CardContent></Card>
          <Card className="lg:col-span-5"><CardContent className="p-3"><div className="h-[180px] skeleton-shimmer rounded" /></CardContent></Card>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header + proxy address */}
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-extrabold tracking-tight bg-gradient-to-b from-white to-white/70 bg-clip-text text-transparent">Dashboard</h1>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-1.5 glass-surface rounded-lg text-sm">
            <code className="font-mono font-semibold text-primary">{proxy}</code>
            <button type="button" onClick={copy} title="Copy proxy address" className="text-primary hover:text-primary/80 btn-press">
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
          <button type="button" onClick={async () => {
              if (!confirm('Reset all counters? This clears proxy logs and WAF stats.')) return;
              const t = toast.loading('Resetting counters...');
              try { await api.post('counters/reset'); toast.success('All counters reset', { id: t }); queryClient.invalidateQueries(); }
              catch { toast.error('Reset failed', { id: t }); }
            }}
            className="flex items-center px-3 py-1.5 bg-destructive/10 text-destructive hover:bg-destructive/20 rounded-lg text-sm font-medium btn-press transition-colors">
            <RotateCcw className="w-3.5 h-3.5 mr-1.5" />Reset
          </button>
          <button type="button" onClick={() => window.open('/api/analytics/report/pdf', '_blank')}
            className="flex items-center px-3 py-1.5 glass-surface text-foreground hover:bg-white/[0.06] rounded-lg text-sm font-medium btn-press transition-colors">
            <Download className="w-3.5 h-3.5 mr-1.5" />PDF
          </button>
        </div>
      </div>

      {/* Compact stats row — staggered entrance */}
      <div className="grid gap-3 grid-cols-2 lg:grid-cols-6">
        <Card className="stagger-child" style={{ '--stagger-index': 0 } as React.CSSProperties}>
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Today</p>
            <p className="text-2xl font-bold">{animToday.toLocaleString()}</p>
            <p className="text-[10px] text-muted-foreground">{s?.today_blocked ?? 0} blocked</p>
          </CardContent>
        </Card>
        <Card className="stagger-child" style={{ '--stagger-index': 1 } as React.CSSProperties}>
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total</p>
            <p className="text-2xl font-bold">{animTotal.toLocaleString()}</p>
            <p className="text-[10px] text-muted-foreground">all time</p>
          </CardContent>
        </Card>
        <Card className="stagger-child" style={{ '--stagger-index': 2 } as React.CSSProperties}>
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Block Rate</p>
            <p className={`text-2xl font-bold ${parseFloat(rate) > 50 ? 'text-destructive' : parseFloat(rate) > 10 ? 'text-yellow-500' : 'text-emerald-500'}`}>{rate}%</p>
            <p className="text-[10px] text-muted-foreground">{animBlocked.toLocaleString()} blocked</p>
          </CardContent>
        </Card>
        <Card className="stagger-child" style={{ '--stagger-index': 3 } as React.CSSProperties}>
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Score</p>
            <p className="text-2xl font-bold">{animScore}<span className="text-sm text-muted-foreground">/100</span></p>
            <div className="w-full bg-secondary h-1.5 mt-1 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full progress-glow ${(sec?.score || 0) > 80 ? 'bg-emerald-500 glow-emerald' : (sec?.score || 0) > 50 ? 'bg-yellow-500 glow-yellow' : 'bg-destructive glow-destructive'}`}
                style={{ width: `${sec?.score || 0}%` }}
              />
            </div>
          </CardContent>
        </Card>
        <Card className="stagger-child" style={{ '--stagger-index': 4 } as React.CSSProperties}>
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">IP Rules</p>
            <p className="text-2xl font-bold">{animIpRules.toLocaleString()}</p>
            <p className="text-[10px] text-muted-foreground">{(s?.domain_blacklist_count ?? 0).toLocaleString()} domains</p>
          </CardContent>
        </Card>
        {w && (
          <Card className="stagger-child" style={{ '--stagger-index': 5 } as React.CSSProperties}>
            <CardContent className="p-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">WAF</p>
              <p className="text-2xl font-bold">{w.requests_last_minute}<span className="text-sm text-muted-foreground">/min</span></p>
              <p className="text-[10px] text-muted-foreground">{w.total_blocked} blocked, entropy {w.avg_url_entropy}</p>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Chart + Threat categories + Top blocked — 3 columns */}
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
                    <linearGradient id="cT" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/><stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/></linearGradient>
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
            {(s?.threat_categories?.length ?? 0) > 0 && s ? (
              <>
                <div className="h-[130px]">
                  <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                    <PieChart><Pie data={s.threat_categories} dataKey="count" nameKey="category" cx="50%" cy="50%" innerRadius={35} outerRadius={55} paddingAngle={3}>
                      {s.threat_categories.map((_: unknown, i: number) => <Cell key={i} fill={C[i % C.length]} />)}
                    </Pie><Tooltip contentStyle={TOOLTIP_STYLE} /></PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-wrap gap-1 mt-1">{s.threat_categories.map((c: { category: string; count: number }, i: number) => (
                  <span key={c.category} className="text-[10px] px-1.5 py-0.5 rounded-full border" style={{ borderColor: C[i % C.length] + '40', color: C[i % C.length] }}>{c.category} ({c.count})</span>
                ))}</div>
              </>
            ) : <div className="h-[180px] flex items-center justify-center text-muted-foreground text-xs">No threats</div>}
          </CardContent>
        </Card>

        {/* Top blocked */}
        <Card className="lg:col-span-4">
          <CardHeader className="p-3 pb-0">
            <CardTitle className="text-sm flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5 text-destructive" />Top Blocked (24h)</CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            <div className="space-y-1 max-h-[180px] overflow-y-auto custom-scrollbar">
              {s?.top_blocked?.slice(0, 8).map((item: { dest: string; count: number }, i: number) => (
                <div key={i} className="flex items-center justify-between py-1 text-xs row-hover rounded px-1">
                  <span className="truncate max-w-[200px] text-muted-foreground font-mono" title={item.dest}>{item.dest}</span>
                  <span className="font-bold text-destructive ml-2 shrink-0">{item.count}</span>
                </div>
              ))}
              {(!s?.top_blocked?.length) && <div className="text-center py-6 text-muted-foreground text-xs">No blocks in 24h</div>}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent blocks + WAF + Cache — 3 columns */}
      <div className="grid gap-3 lg:grid-cols-3">
        <Card>
          <CardHeader className="p-3 pb-0">
            <CardTitle className="text-sm flex items-center gap-1.5"><Zap className="w-3.5 h-3.5 text-yellow-500" />Recent Blocks</CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            <div className="space-y-0.5 max-h-[160px] overflow-y-auto custom-scrollbar">
              {s?.recent_blocks?.slice(0, 8).map((b: { timestamp: string; source_ip: string; destination: string; status: string }, i: number) => (
                <div key={i} className="flex items-center justify-between py-1 text-xs row-hover rounded px-1">
                  <div className="overflow-hidden mr-2">
                    <p className="truncate max-w-[280px] font-mono">{b.destination}</p>
                    <p className="text-[10px] text-muted-foreground">{b.source_ip} {new Date(b.timestamp).toLocaleTimeString()}</p>
                  </div>
                  <span className={`text-[9px] px-1.5 py-0.5 rounded-full font-medium shrink-0 ${b.status?.includes('403') ? 'bg-destructive/10 text-destructive' : 'bg-orange-500/10 text-orange-500'}`}>
                    {b.status?.includes('403') ? 'WAF' : 'DENY'}
                  </span>
                </div>
              ))}
              {(!s?.recent_blocks?.length) && <div className="text-center py-6 text-muted-foreground text-xs">No recent blocks</div>}
            </div>
          </CardContent>
        </Card>

        {w && (
          <Card>
            <CardHeader className="p-3 pb-0">
              <CardTitle className="text-sm flex items-center gap-1.5"><Brain className="w-3.5 h-3.5 text-primary" />WAF Intelligence</CardTitle>
            </CardHeader>
            <CardContent className="p-2">
              <div className="grid grid-cols-3 gap-2 mb-2">
                <div><p className="text-[10px] text-muted-foreground uppercase">Inspected</p><p className="text-lg font-bold">{w.total_requests.toLocaleString()}</p></div>
                <div><p className="text-[10px] text-muted-foreground uppercase">Blocked</p><p className="text-lg font-bold text-destructive">{w.total_blocked}</p></div>
                <div><p className="text-[10px] text-muted-foreground uppercase">Entropy</p><p className="text-lg font-bold">{w.avg_url_entropy}</p></div>
              </div>
              {w.top_blocked_categories?.length > 0 && (
                <div className="flex flex-wrap gap-1 pt-2 border-t border-white/[0.06]">
                  {w.top_blocked_categories.slice(0, 6).map((c: { key: string; count: number }) => (
                    <span key={c.key} className="px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-destructive/10 text-destructive border border-destructive/20">{c.key} ({c.count})</span>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Cache Efficiency */}
        <Card>
          <CardHeader className="p-3 pb-0">
            <CardTitle className="text-sm flex items-center gap-1.5">
              <svg className="w-3.5 h-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
              Cache
            </CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            {cache ? (() => {
              const hitRate = cache.hit_ratio != null ? (cache.hit_ratio * 100).toFixed(1) : cache.hits && cache.requests ? ((cache.hits / cache.requests) * 100).toFixed(1) : '0';
              const saved = Number(cache.bytes_saved || 0);
              const formatBytes = (b: number) => { if (b < 1024) return `${b} B`; if (b < 1048576) return `${(b/1024).toFixed(1)} KB`; if (b < 1073741824) return `${(b/1048576).toFixed(1)} MB`; return `${(b/1073741824).toFixed(2)} GB`; };
              return (
                <div className="space-y-2">
                  <div className="flex items-baseline justify-between">
                    <span className="text-[10px] text-muted-foreground uppercase">Hit Rate</span>
                    <span className={`text-lg font-bold ${parseFloat(hitRate) > 50 ? 'text-emerald-500' : parseFloat(hitRate) > 20 ? 'text-yellow-500' : 'text-muted-foreground'}`}>{hitRate}%</span>
                  </div>
                  <div className="w-full bg-secondary h-2 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full progress-glow ${parseFloat(hitRate) > 50 ? 'bg-emerald-500 glow-emerald' : parseFloat(hitRate) > 20 ? 'bg-yellow-500 glow-yellow' : 'bg-muted-foreground'}`}
                      style={{ width: `${Math.min(parseFloat(hitRate), 100)}%` }}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-2 pt-1">
                    <div>
                      <p className="text-[10px] text-muted-foreground">Hits</p>
                      <p className="text-sm font-bold">{(cache.hits || 0).toLocaleString()}</p>
                    </div>
                    <div>
                      <p className="text-[10px] text-muted-foreground">Misses</p>
                      <p className="text-sm font-bold">{(cache.misses || 0).toLocaleString()}</p>
                    </div>
                  </div>
                  {saved > 0 && (
                    <div className="pt-1 border-t border-white/[0.06]">
                      <p className="text-[10px] text-muted-foreground">Bandwidth Saved</p>
                      <p className="text-sm font-bold text-emerald-500">{formatBytes(saved)}</p>
                    </div>
                  )}
                </div>
              );
            })() : (
              <div className="py-6 text-center text-xs text-muted-foreground">Loading cache stats...</div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
