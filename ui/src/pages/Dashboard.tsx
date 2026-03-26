import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Zap, Download, Copy, Check, Brain, AlertTriangle, RotateCcw } from 'lucide-react';
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell, PieChart, Pie } from 'recharts';
import React, { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { api } from '../lib/api';
import type { TimelineEntry, SecurityScore } from '../types';

const REFETCH = 10_000;
const C = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#ec4899'];

export function Dashboard() {
  const queryClient = useQueryClient();
  const [copied, setCopied] = useState(false);
  const proxy = `${window.location.hostname}:3128`;
  const copy = () => { navigator.clipboard.writeText(proxy); setCopied(true); setTimeout(() => setCopied(false), 2000); };

  const [vis, setVis] = useState(document.visibilityState !== 'hidden');
  useEffect(() => { const h = () => setVis(document.visibilityState !== 'hidden'); document.addEventListener('visibilitychange', h); return () => document.removeEventListener('visibilitychange', h); }, []);

  const { data: s } = useQuery<any>({ queryKey: ['dashboard'], queryFn: () => api.get('dashboard/summary').then(r => r.data.data), refetchInterval: vis ? REFETCH : false });
  const { data: tl } = useQuery<TimelineEntry[]>({ queryKey: ['timeline'], queryFn: () => api.get('logs/timeline').then(r => r.data.data), refetchInterval: vis ? REFETCH : false });
  const { data: sec } = useQuery<SecurityScore>({ queryKey: ['score'], queryFn: () => api.get('security/score').then(r => r.data.data), refetchInterval: vis ? 30_000 : false });

  const chart = React.useMemo(() => tl ?? [], [tl]);
  const rate = s?.total_requests ? ((s.blocked_requests / s.total_requests) * 100).toFixed(1) : '0';
  const w = s?.waf;

  return (
    <div className="space-y-4 animate-in fade-in duration-500">
      {/* Header + proxy address */}
      <div className="flex justify-between items-center">
        <h1 className="text-xl font-bold tracking-tight">Dashboard</h1>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-primary/5 border border-primary/20 rounded-md text-sm">
            <code className="font-mono font-semibold text-primary">{proxy}</code>
            <button type="button" onClick={copy} className="text-primary hover:text-primary/80">
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
          <button type="button" onClick={async () => {
              if (!confirm('Reset all counters? This clears proxy logs and WAF stats.')) return;
              const t = toast.loading('Resetting counters...');
              try { await api.post('counters/reset'); toast.success('All counters reset', { id: t }); queryClient.invalidateQueries(); }
              catch { toast.error('Reset failed', { id: t }); }
            }}
            className="flex items-center px-3 py-1.5 bg-destructive/10 text-destructive hover:bg-destructive/20 rounded-md text-sm font-medium">
            <RotateCcw className="w-3.5 h-3.5 mr-1.5" />Reset
          </button>
          <button type="button" onClick={() => window.open('/api/analytics/report/pdf', '_blank')}
            className="flex items-center px-3 py-1.5 bg-secondary text-foreground hover:bg-secondary/80 rounded-md text-sm font-medium">
            <Download className="w-3.5 h-3.5 mr-1.5" />PDF
          </button>
        </div>
      </div>

      {/* Compact stats row */}
      <div className="grid gap-3 grid-cols-2 lg:grid-cols-6">
        <Card className="bg-card/50">
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Today</p>
            <p className="text-2xl font-bold">{(s?.today_requests ?? 0).toLocaleString()}</p>
            <p className="text-[10px] text-muted-foreground">{s?.today_blocked ?? 0} blocked</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total</p>
            <p className="text-2xl font-bold">{(s?.total_requests ?? 0).toLocaleString()}</p>
            <p className="text-[10px] text-muted-foreground">all time</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Block Rate</p>
            <p className={`text-2xl font-bold ${parseFloat(rate) > 50 ? 'text-destructive' : parseFloat(rate) > 10 ? 'text-yellow-500' : 'text-emerald-500'}`}>{rate}%</p>
            <p className="text-[10px] text-muted-foreground">{(s?.blocked_requests ?? 0).toLocaleString()} blocked</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Score</p>
            <p className="text-2xl font-bold">{sec?.score || 0}<span className="text-sm text-muted-foreground">/100</span></p>
            <div className="w-full bg-secondary h-1.5 mt-1 rounded-full overflow-hidden">
              <div className={`h-full ${(sec?.score || 0) > 80 ? 'bg-emerald-500' : (sec?.score || 0) > 50 ? 'bg-yellow-500' : 'bg-destructive'}`} style={{ width: `${sec?.score || 0}%` }} />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">IP Rules</p>
            <p className="text-2xl font-bold">{(s?.ip_blacklist_count ?? 0).toLocaleString()}</p>
            <p className="text-[10px] text-muted-foreground">{(s?.domain_blacklist_count ?? 0).toLocaleString()} domains</p>
          </CardContent>
        </Card>
        {w && (
          <Card className="bg-card/50">
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
        <Card className="lg:col-span-5 bg-card/50">
          <CardHeader className="p-3 pb-0">
            <CardTitle className="text-sm">Traffic 24h</CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            <div className="h-[180px]">
              <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                <AreaChart data={chart} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="cT" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/><stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/></linearGradient>
                    <linearGradient id="cB" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#888" fontSize={9} tickLine={false} axisLine={false} />
                  <YAxis stroke="#888" fontSize={9} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '6px', fontSize: '12px' }} />
                  <Area type="monotone" dataKey="total" name="Total" stroke="#3b82f6" strokeWidth={1.5} fill="url(#cT)" />
                  <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#ef4444" strokeWidth={1.5} fill="url(#cB)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Threat categories pie */}
        <Card className="lg:col-span-3 bg-card/50">
          <CardHeader className="p-3 pb-0">
            <CardTitle className="text-sm">Threats</CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            {s?.threat_categories?.length > 0 ? (
              <>
                <div className="h-[130px]">
                  <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                    <PieChart><Pie data={s.threat_categories} dataKey="count" nameKey="category" cx="50%" cy="50%" innerRadius={35} outerRadius={55} paddingAngle={3}>
                      {s.threat_categories.map((_: any, i: number) => <Cell key={i} fill={C[i % C.length]} />)}
                    </Pie><Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '6px', fontSize: '11px' }} /></PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-wrap gap-1 mt-1">{s.threat_categories.map((c: any, i: number) => (
                  <span key={c.category} className="text-[10px] px-1.5 py-0.5 rounded-full border" style={{ borderColor: C[i % C.length] + '40', color: C[i % C.length] }}>{c.category} ({c.count})</span>
                ))}</div>
              </>
            ) : <div className="h-[180px] flex items-center justify-center text-muted-foreground text-xs">No threats</div>}
          </CardContent>
        </Card>

        {/* Top blocked */}
        <Card className="lg:col-span-4 bg-card/50">
          <CardHeader className="p-3 pb-0">
            <CardTitle className="text-sm flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5 text-destructive" />Top Blocked (24h)</CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            <div className="space-y-1 max-h-[180px] overflow-y-auto">
              {s?.top_blocked?.slice(0, 8).map((item: any, i: number) => (
                <div key={i} className="flex items-center justify-between py-1 text-xs">
                  <span className="truncate max-w-[200px] text-muted-foreground font-mono" title={item.dest}>{item.dest}</span>
                  <span className="font-bold text-destructive ml-2 shrink-0">{item.count}</span>
                </div>
              ))}
              {(!s?.top_blocked?.length) && <div className="text-center py-6 text-muted-foreground text-xs">No blocks in 24h</div>}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent blocks + WAF categories — 2 columns */}
      <div className="grid gap-3 lg:grid-cols-2">
        <Card className="bg-card/50">
          <CardHeader className="p-3 pb-0">
            <CardTitle className="text-sm flex items-center gap-1.5"><Zap className="w-3.5 h-3.5 text-yellow-500" />Recent Blocks</CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            <div className="space-y-0.5 max-h-[160px] overflow-y-auto">
              {s?.recent_blocks?.slice(0, 8).map((b: any, i: number) => (
                <div key={i} className="flex items-center justify-between py-1 text-xs">
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
          <Card className="bg-card/50">
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
                <div className="flex flex-wrap gap-1 pt-2 border-t border-border/30">
                  {w.top_blocked_categories.slice(0, 6).map((c: any) => (
                    <span key={c.key} className="px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-destructive/10 text-destructive border border-destructive/20">{c.key} ({c.count})</span>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
