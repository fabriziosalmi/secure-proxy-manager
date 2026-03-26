import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Shield, Activity, Globe, AlertTriangle, Clock, TrendingUp } from 'lucide-react';
import { BarChart, Bar, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell, AreaChart, Area } from 'recharts';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useEffect, useState } from 'react';
import type { TimelineEntry } from '../types';

const C = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#ec4899'];

export function ThreatIntel() {
  const [vis, setVis] = useState(document.visibilityState !== 'hidden');
  useEffect(() => { const h = () => setVis(document.visibilityState !== 'hidden'); document.addEventListener('visibilitychange', h); return () => document.removeEventListener('visibilitychange', h); }, []);

  const { data: s } = useQuery<any>({ queryKey: ['dashboard'], queryFn: () => api.get('dashboard/summary').then(r => r.data.data), refetchInterval: vis ? 15_000 : false });
  const { data: tl } = useQuery<TimelineEntry[]>({ queryKey: ['timeline72'], queryFn: () => api.get('logs/timeline?hours=72').then(r => r.data.data), refetchInterval: vis ? 30_000 : false });

  const wafCats = s?.waf?.top_blocked_categories ?? [];

  return (
    <div className="space-y-4 animate-in fade-in duration-500">
      <h1 className="text-xl font-bold tracking-tight">Threat Intelligence</h1>

      {/* Compact metrics */}
      <div className="grid gap-3 grid-cols-2 lg:grid-cols-5">
        <Card className="bg-card/50 border-destructive/20">
          <CardContent className="p-3 flex items-center justify-between">
            <div><p className="text-[10px] text-muted-foreground uppercase">Today</p><p className="text-2xl font-bold text-destructive">{(s?.today_blocked ?? 0).toLocaleString()}</p></div>
            <AlertTriangle className="w-6 h-6 text-destructive/30" />
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-3 flex items-center justify-between">
            <div><p className="text-[10px] text-muted-foreground uppercase">Total Blocks</p><p className="text-2xl font-bold">{(s?.blocked_requests ?? 0).toLocaleString()}</p></div>
            <Shield className="w-6 h-6 text-primary/30" />
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-3 flex items-center justify-between">
            <div><p className="text-[10px] text-muted-foreground uppercase">WAF Blocks</p><p className="text-2xl font-bold text-orange-500">{s?.waf?.total_blocked ?? 0}</p></div>
            <Activity className="w-6 h-6 text-orange-500/30" />
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-3 flex items-center justify-between">
            <div><p className="text-[10px] text-muted-foreground uppercase">Categories</p><p className="text-2xl font-bold">{wafCats.length}</p></div>
            <Globe className="w-6 h-6 text-muted-foreground/30" />
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-3 flex items-center justify-between">
            <div><p className="text-[10px] text-muted-foreground uppercase">Entropy Alerts</p><p className="text-2xl font-bold text-yellow-500">{s?.waf?.high_entropy_count ?? 0}</p></div>
            <TrendingUp className="w-6 h-6 text-yellow-500/30" />
          </CardContent>
        </Card>
      </div>

      {/* Timeline + WAF categories side by side */}
      <div className="grid gap-3 lg:grid-cols-12">
        <Card className="lg:col-span-7 bg-card/50">
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm">Threat Timeline (72h)</CardTitle></CardHeader>
          <CardContent className="p-2">
            <div className="h-[200px]">
              <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                <AreaChart data={tl ?? []} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <defs><linearGradient id="bg" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient></defs>
                  <XAxis dataKey="time" stroke="#888" fontSize={9} tickLine={false} axisLine={false} />
                  <YAxis stroke="#888" fontSize={9} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '6px', fontSize: '11px' }} />
                  <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#ef4444" strokeWidth={2} fill="url(#bg)" />
                  <Area type="monotone" dataKey="total" name="Total" stroke="#3b82f6" strokeWidth={1} fill="none" opacity={0.4} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-5 bg-card/50">
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm">WAF Categories</CardTitle></CardHeader>
          <CardContent className="p-2">
            {wafCats.length > 0 ? (
              <div className="h-[200px]">
                <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                  <BarChart data={wafCats.slice(0, 8)} layout="vertical" margin={{ left: 80, right: 10 }}>
                    <XAxis type="number" stroke="#888" fontSize={9} tickLine={false} />
                    <YAxis type="category" dataKey="key" stroke="#888" fontSize={9} tickLine={false} width={80} />
                    <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '6px', fontSize: '11px' }} />
                    <Bar dataKey="count" radius={[0, 3, 3, 0]}>{wafCats.slice(0, 8).map((_: any, i: number) => <Cell key={i} fill={C[i % C.length]} />)}</Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : <div className="h-[200px] flex items-center justify-center text-muted-foreground text-xs">No WAF blocks</div>}
          </CardContent>
        </Card>
      </div>

      {/* Top blocked + Live feed — 2 columns */}
      <div className="grid gap-3 lg:grid-cols-2">
        <Card className="bg-card/50">
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm">Top Blocked Destinations</CardTitle></CardHeader>
          <CardContent className="p-2">
            <div className="space-y-1 max-h-[220px] overflow-y-auto">
              {s?.top_blocked?.map((item: any, i: number) => (
                <div key={i} className="flex items-center gap-2 py-1 text-xs">
                  <span className="text-muted-foreground w-4 text-right font-bold">{i + 1}</span>
                  <span className="font-mono truncate flex-1" title={item.dest}>{item.dest}</span>
                  <div className="w-12 bg-secondary h-1.5 rounded-full overflow-hidden shrink-0">
                    <div className="h-full bg-destructive rounded-full" style={{ width: `${Math.min(100, (item.count / (s?.top_blocked?.[0]?.count || 1)) * 100)}%` }} />
                  </div>
                  <span className="font-bold text-destructive w-6 text-right">{item.count}</span>
                </div>
              ))}
              {(!s?.top_blocked?.length) && <div className="text-center py-8 text-muted-foreground text-xs">No blocked destinations</div>}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm flex items-center gap-1.5"><Clock className="w-3.5 h-3.5 text-yellow-500" />Live Threat Feed</CardTitle></CardHeader>
          <CardContent className="p-2">
            <div className="space-y-0.5 max-h-[220px] overflow-y-auto">
              {s?.recent_blocks?.map((b: any, i: number) => (
                <div key={i} className="flex items-center py-1 px-2 rounded hover:bg-secondary/20 text-xs">
                  <div className="w-1.5 h-1.5 rounded-full bg-destructive mr-2 shrink-0 animate-pulse" />
                  <span className="text-muted-foreground w-16 shrink-0 font-mono text-[10px]">{new Date(b.timestamp).toLocaleTimeString()}</span>
                  <span className="text-muted-foreground w-24 shrink-0 font-mono text-[10px]">{b.source_ip}</span>
                  <span className="truncate flex-1 font-mono" title={b.destination}>{b.destination}</span>
                  <span className={`text-[9px] px-1.5 py-0.5 rounded-full font-medium shrink-0 ml-1 ${b.status?.includes('403') ? 'bg-destructive/10 text-destructive' : 'bg-orange-500/10 text-orange-500'}`}>
                    {b.status?.includes('403') ? 'WAF' : 'DENY'}
                  </span>
                </div>
              ))}
              {(!s?.recent_blocks?.length) && <div className="text-center py-8 text-muted-foreground text-xs">No threats detected</div>}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
