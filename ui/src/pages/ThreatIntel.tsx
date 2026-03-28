import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Shield, Activity, Globe, AlertTriangle, Clock, TrendingUp, Eye, FileType, Cloud } from 'lucide-react';
import { BarChart, Bar, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell, AreaChart, Area, PieChart, Pie } from 'recharts';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useEffect, useState } from 'react';
import type { TimelineEntry, DashboardSummary, ShadowItService, FileExtData, ServiceTypeData, TopDomain } from '../types';
import { RegexPlayground } from '../components/RegexPlayground';

const C = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#ec4899', '#14b8a6', '#6366f1'];
const CAT_COLORS: Record<string, string> = {
  'File Sharing': '#ef4444', Messaging: '#f97316', Productivity: '#eab308', AI: '#8b5cf6',
  Social: '#3b82f6', Streaming: '#06b6d4', Tunneling: '#ef4444', 'Paste/Code': '#f59e0b',
};

export function ThreatIntel() {
  const [vis, setVis] = useState(document.visibilityState !== 'hidden');
  useEffect(() => { const h = () => setVis(document.visibilityState !== 'hidden'); document.addEventListener('visibilitychange', h); return () => document.removeEventListener('visibilitychange', h); }, []);

  const { data: s } = useQuery<DashboardSummary>({ queryKey: ['dashboard'], queryFn: () => api.get('dashboard/summary').then(r => r.data.data), refetchInterval: vis ? 15_000 : false });
  const { data: tl } = useQuery<TimelineEntry[]>({ queryKey: ['timeline72'], queryFn: () => api.get('logs/timeline?hours=72').then(r => r.data.data), refetchInterval: vis ? 30_000 : false });
  const { data: shadowIt } = useQuery<ShadowItService[]>({ queryKey: ['shadow-it'], queryFn: () => api.get('analytics/shadow-it').then(r => r.data.data), refetchInterval: vis ? 60_000 : false });
  const { data: fileExts } = useQuery<FileExtData>({ queryKey: ['file-exts'], queryFn: () => api.get('analytics/file-extensions').then(r => r.data.data), refetchInterval: vis ? 60_000 : false });
  const { data: topDomains } = useQuery<TopDomain[]>({ queryKey: ['top-domains'], queryFn: () => api.get('analytics/top-domains').then(r => r.data.data), refetchInterval: vis ? 60_000 : false });
  const { data: uaData } = useQuery<ServiceTypeData>({ queryKey: ['user-agents'], queryFn: () => api.get('analytics/user-agents').then(r => r.data.data), refetchInterval: vis ? 60_000 : false });

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
            <div><p className="text-[10px] text-muted-foreground uppercase">SaaS Detected</p><p className="text-2xl font-bold text-blue-500">{shadowIt?.length ?? 0}</p></div>
            <Cloud className="w-6 h-6 text-blue-500/30" />
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-3 flex items-center justify-between">
            <div><p className="text-[10px] text-muted-foreground uppercase">Entropy Alerts</p><p className="text-2xl font-bold text-yellow-500">{s?.waf?.high_entropy_count ?? 0}</p></div>
            <TrendingUp className="w-6 h-6 text-yellow-500/30" />
          </CardContent>
        </Card>
      </div>

      {/* Timeline + WAF categories */}
      <div className="grid gap-3 lg:grid-cols-12">
        <Card className="lg:col-span-7 bg-card/50">
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm">Threat Timeline (72h)</CardTitle></CardHeader>
          <CardContent className="p-2">
            <div className="h-[180px]">
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
              <div className="h-[180px]">
                <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                  <BarChart data={wafCats.slice(0, 8)} layout="vertical" margin={{ left: 80, right: 10 }}>
                    <XAxis type="number" stroke="#888" fontSize={9} tickLine={false} />
                    <YAxis type="category" dataKey="key" stroke="#888" fontSize={9} tickLine={false} width={80} />
                    <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '6px', fontSize: '11px' }} />
                    <Bar dataKey="count" radius={[0, 3, 3, 0]}>{wafCats.slice(0, 8).map((_: unknown, i: number) => <Cell key={i} fill={C[i % C.length]} />)}</Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : <div className="h-[180px] flex items-center justify-center text-muted-foreground text-xs">No WAF blocks</div>}
          </CardContent>
        </Card>
      </div>

      {/* Shadow IT + File Extensions + Service Types — 3 columns */}
      <div className="grid gap-3 lg:grid-cols-3">
        {/* Shadow IT Detector */}
        <Card className="bg-card/50">
          <CardHeader className="p-3 pb-0">
            <CardTitle className="text-sm flex items-center gap-1.5"><Eye className="w-3.5 h-3.5 text-blue-500" />Shadow IT</CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            <div className="space-y-0.5 max-h-[200px] overflow-y-auto">
              {shadowIt && shadowIt.length > 0 ? shadowIt.slice(0, 15).map((svc, i) => (
                <div key={i} className="flex items-center justify-between py-1 text-xs">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: CAT_COLORS[svc.category] || '#6b7280' }} />
                    <span className="font-medium truncate">{svc.name}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-secondary text-muted-foreground">{svc.category}</span>
                    <span className="font-bold text-muted-foreground w-8 text-right">{svc.requests}</span>
                  </div>
                </div>
              )) : <div className="text-center py-6 text-muted-foreground text-xs">No SaaS services detected</div>}
            </div>
          </CardContent>
        </Card>

        {/* File Extension Distribution */}
        <Card className="bg-card/50">
          <CardHeader className="p-3 pb-0">
            <CardTitle className="text-sm flex items-center gap-1.5"><FileType className="w-3.5 h-3.5 text-emerald-500" />File Types</CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            {(fileExts?.categories?.length ?? 0) > 0 ? (
              <>
                <div className="h-[120px]">
                  <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                    <PieChart><Pie data={fileExts!.categories.slice(0, 8)} dataKey="count" nameKey="category" cx="50%" cy="50%" innerRadius={30} outerRadius={50} paddingAngle={2}>
                      {fileExts!.categories.slice(0, 8).map((_, i) => <Cell key={i} fill={C[i % C.length]} />)}
                    </Pie><Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '6px', fontSize: '11px' }} /></PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-wrap gap-1 mt-1">
                  {fileExts!.categories.slice(0, 6).map((c, i) => (
                    <span key={c.category} className="text-[9px] px-1.5 py-0.5 rounded-full border" style={{ borderColor: C[i % C.length] + '40', color: C[i % C.length] }}>{c.category} ({c.count})</span>
                  ))}
                </div>
              </>
            ) : <div className="h-[200px] flex items-center justify-center text-muted-foreground text-xs">No file data</div>}
          </CardContent>
        </Card>

        {/* Service Types (UA proxy) */}
        <Card className="bg-card/50">
          <CardHeader className="p-3 pb-0">
            <CardTitle className="text-sm flex items-center gap-1.5"><Globe className="w-3.5 h-3.5 text-purple-500" />Service Types</CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            {(uaData?.service_types?.length ?? 0) > 0 ? (
              <div className="space-y-1">
                {uaData!.service_types.slice(0, 10).map((st, i) => {
                  const max = uaData!.service_types[0].count;
                  return (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <span className="w-24 truncate text-muted-foreground">{st.name}</span>
                      <div className="flex-1 bg-secondary h-2 rounded-full overflow-hidden">
                        <div className="h-full rounded-full" style={{ width: `${(st.count / max) * 100}%`, backgroundColor: C[i % C.length] }} />
                      </div>
                      <span className="font-bold w-8 text-right text-muted-foreground">{st.count}</span>
                    </div>
                  );
                })}
              </div>
            ) : <div className="h-[200px] flex items-center justify-center text-muted-foreground text-xs">No service data</div>}
          </CardContent>
        </Card>
      </div>

      {/* Domain Cloud + Top Blocked + Live Feed — 3 columns */}
      <div className="grid gap-3 lg:grid-cols-3">
        {/* Domain Cloud */}
        <Card className="bg-card/50">
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm">Top Domains</CardTitle></CardHeader>
          <CardContent className="p-2">
            {topDomains && topDomains.length > 0 ? (
              <div className="flex flex-wrap gap-1 max-h-[200px] overflow-y-auto">
                {topDomains.slice(0, 40).map((d, i) => {
                  const maxCount = topDomains[0].count;
                  const ratio = d.count / maxCount;
                  const size = Math.max(10, Math.min(20, 10 + ratio * 10));
                  const opacity = Math.max(0.4, ratio);
                  return (
                    <span
                      key={d.domain}
                      className="px-1.5 py-0.5 rounded cursor-default hover:bg-secondary/50 transition-colors font-mono"
                      style={{ fontSize: `${size}px`, opacity, color: C[i % C.length] }}
                      title={`${d.domain}: ${d.count} requests`}
                    >
                      {d.domain}
                    </span>
                  );
                })}
              </div>
            ) : <div className="h-[200px] flex items-center justify-center text-muted-foreground text-xs">No domain data</div>}
          </CardContent>
        </Card>

        {/* Top blocked */}
        <Card className="bg-card/50">
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm">Top Blocked</CardTitle></CardHeader>
          <CardContent className="p-2">
            <div className="space-y-1 max-h-[200px] overflow-y-auto">
              {s?.top_blocked?.map((item, i) => (
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

        {/* Live feed */}
        <Card className="bg-card/50">
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm flex items-center gap-1.5"><Clock className="w-3.5 h-3.5 text-yellow-500" />Live Feed</CardTitle></CardHeader>
          <CardContent className="p-2">
            <div className="space-y-0.5 max-h-[200px] overflow-y-auto">
              {s?.recent_blocks?.map((b, i) => (
                <div key={i} className="flex items-center py-1 px-1 rounded hover:bg-secondary/20 text-xs">
                  <div className="w-1.5 h-1.5 rounded-full bg-destructive mr-2 shrink-0 animate-pulse" />
                  <span className="text-muted-foreground w-14 shrink-0 font-mono text-[10px]">{new Date(b.timestamp).toLocaleTimeString()}</span>
                  <span className="truncate flex-1 font-mono" title={b.destination}>{b.destination}</span>
                  <span className={`text-[9px] px-1 py-0.5 rounded-full font-medium shrink-0 ml-1 ${b.status?.includes('403') ? 'bg-destructive/10 text-destructive' : 'bg-orange-500/10 text-orange-500'}`}>
                    {b.status?.includes('403') ? 'WAF' : 'DENY'}
                  </span>
                </div>
              ))}
              {(!s?.recent_blocks?.length) && <div className="text-center py-8 text-muted-foreground text-xs">No threats</div>}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Regex Playground */}
      <RegexPlayground />
    </div>
  );
}
