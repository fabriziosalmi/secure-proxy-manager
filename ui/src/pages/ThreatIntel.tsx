import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Shield, Activity, Globe, AlertTriangle, Clock, TrendingUp, Eye, FileType, Cloud } from 'lucide-react';
import { BarChart, Bar, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell, AreaChart, Area, PieChart, Pie } from 'recharts';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useEffect, useState } from 'react';
import { useAnimatedNumber } from '../hooks/useAnimatedNumber';
import type { TimelineEntry, DashboardSummary, ShadowItService, FileExtData, ServiceTypeData, TopDomain } from '../types';
import { RegexPlayground } from '../components/RegexPlayground';

const C = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#ec4899', '#14b8a6', '#6366f1'];
const CAT_COLORS: Record<string, string> = {
  'File Sharing': '#ef4444', Messaging: '#f97316', Productivity: '#eab308', AI: '#8b5cf6',
  Social: '#3b82f6', Streaming: '#06b6d4', Tunneling: '#ef4444', 'Paste/Code': '#f59e0b',
};

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

export function ThreatIntel() {
  const [vis, setVis] = useState(document.visibilityState !== 'hidden');
  useEffect(() => { const h = () => setVis(document.visibilityState !== 'hidden'); document.addEventListener('visibilitychange', h); return () => document.removeEventListener('visibilitychange', h); }, []);

  const { data: s } = useQuery<DashboardSummary>({ queryKey: ['dashboard'], queryFn: () => api.get('dashboard/summary').then(r => r.data.data), refetchInterval: vis ? 30_000 : false });
  const { data: tl } = useQuery<TimelineEntry[]>({ queryKey: ['timeline72'], queryFn: () => api.get('logs/timeline?hours=72').then(r => r.data.data), refetchInterval: vis ? 60_000 : false });
  const { data: shadowIt } = useQuery<ShadowItService[]>({ queryKey: ['shadow-it'], queryFn: () => api.get('analytics/shadow-it').then(r => r.data.data), refetchInterval: vis ? 60_000 : false });
  const { data: fileExts } = useQuery<FileExtData>({ queryKey: ['file-exts'], queryFn: () => api.get('analytics/file-extensions').then(r => r.data.data), refetchInterval: vis ? 60_000 : false });
  const { data: topDomains } = useQuery<TopDomain[]>({ queryKey: ['top-domains'], queryFn: () => api.get('analytics/top-domains').then(r => r.data.data), refetchInterval: vis ? 60_000 : false });
  const { data: uaData } = useQuery<ServiceTypeData>({ queryKey: ['user-agents'], queryFn: () => api.get('analytics/user-agents').then(r => r.data.data), refetchInterval: vis ? 60_000 : false });

  const wafCats = s?.waf?.top_blocked_categories ?? [];

  const animTodayBlocked = useAnimatedNumber(s?.today_blocked ?? 0);
  const animTotalBlocked = useAnimatedNumber(s?.blocked_requests ?? 0);
  const animWafBlocked = useAnimatedNumber(s?.waf?.total_blocked ?? 0);
  const animSaas = useAnimatedNumber(shadowIt?.length ?? 0);
  const animEntropy = useAnimatedNumber(s?.waf?.high_entropy_count ?? 0);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-extrabold tracking-tight bg-gradient-to-b from-white to-white/70 bg-clip-text text-transparent">Threat Intelligence</h1>

      {/* Compact metrics */}
      <div className="grid gap-3 grid-cols-2 lg:grid-cols-5">
        <Card className="stagger-child border-destructive/20" style={{ '--stagger-index': 0 } as React.CSSProperties}>
          <CardContent className="p-3 flex items-center justify-between">
            <div><p className="text-[10px] text-muted-foreground uppercase">Today</p><p className="text-2xl font-bold text-destructive">{animTodayBlocked.toLocaleString()}</p></div>
            <AlertTriangle className="w-6 h-6 text-destructive/30" />
          </CardContent>
        </Card>
        <Card className="stagger-child" style={{ '--stagger-index': 1 } as React.CSSProperties}>
          <CardContent className="p-3 flex items-center justify-between">
            <div><p className="text-[10px] text-muted-foreground uppercase">Total Blocks</p><p className="text-2xl font-bold">{animTotalBlocked.toLocaleString()}</p></div>
            <Shield className="w-6 h-6 text-primary/30" />
          </CardContent>
        </Card>
        <Card className="stagger-child" style={{ '--stagger-index': 2 } as React.CSSProperties}>
          <CardContent className="p-3 flex items-center justify-between">
            <div><p className="text-[10px] text-muted-foreground uppercase">WAF Blocks</p><p className="text-2xl font-bold text-orange-500">{animWafBlocked.toLocaleString()}</p></div>
            <Activity className="w-6 h-6 text-orange-500/30" />
          </CardContent>
        </Card>
        <Card className="stagger-child" style={{ '--stagger-index': 3 } as React.CSSProperties}>
          <CardContent className="p-3 flex items-center justify-between">
            <div><p className="text-[10px] text-muted-foreground uppercase">SaaS Detected</p><p className="text-2xl font-bold text-blue-500">{animSaas.toLocaleString()}</p></div>
            <Cloud className="w-6 h-6 text-blue-500/30" />
          </CardContent>
        </Card>
        <Card className="stagger-child" style={{ '--stagger-index': 4 } as React.CSSProperties}>
          <CardContent className="p-3 flex items-center justify-between">
            <div><p className="text-[10px] text-muted-foreground uppercase">Entropy Alerts</p><p className="text-2xl font-bold text-yellow-500">{animEntropy.toLocaleString()}</p></div>
            <TrendingUp className="w-6 h-6 text-yellow-500/30" />
          </CardContent>
        </Card>
      </div>

      {/* Timeline + WAF categories */}
      <div className="grid gap-3 lg:grid-cols-12">
        <Card className="lg:col-span-7">
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm">Threat Timeline (72h)</CardTitle></CardHeader>
          <CardContent className="p-2">
            <div className="h-[180px]">
              <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                <AreaChart data={tl ?? []} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <defs><linearGradient id="bg" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient></defs>
                  <XAxis dataKey="time" stroke="#555" fontSize={9} tickLine={false} axisLine={false} />
                  <YAxis stroke="#555" fontSize={9} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#ef4444" strokeWidth={2} fill="url(#bg)" />
                  <Area type="monotone" dataKey="total" name="Total" stroke="#3b82f6" strokeWidth={1} fill="none" opacity={0.4} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-5">
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm">WAF Categories</CardTitle></CardHeader>
          <CardContent className="p-2">
            {wafCats.length > 0 ? (
              <div className="h-[180px]">
                <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                  <BarChart data={wafCats.slice(0, 8)} layout="vertical" margin={{ left: 80, right: 10 }}>
                    <XAxis type="number" stroke="#555" fontSize={9} tickLine={false} />
                    <YAxis type="category" dataKey="key" stroke="#555" fontSize={9} tickLine={false} width={80} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Bar dataKey="count" radius={[0, 3, 3, 0]}>{wafCats.slice(0, 8).map((_: unknown, i: number) => <Cell key={i} fill={C[i % C.length]} />)}</Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : <div className="h-[180px] flex items-center justify-center text-muted-foreground text-xs">No WAF blocks</div>}
          </CardContent>
        </Card>
      </div>

      {/* Shadow IT + File Extensions + Service Types */}
      <div className="grid gap-3 lg:grid-cols-3">
        <Card>
          <CardHeader className="p-3 pb-0">
            <CardTitle className="text-sm flex items-center gap-1.5"><Eye className="w-3.5 h-3.5 text-blue-500" />Shadow IT</CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            <div className="space-y-0.5 max-h-[200px] overflow-y-auto custom-scrollbar">
              {shadowIt && shadowIt.length > 0 ? shadowIt.slice(0, 15).map((svc, i) => (
                <div key={i} className="flex items-center justify-between py-1 text-xs row-hover rounded px-1">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: CAT_COLORS[svc.category] || '#6b7280' }} />
                    <span className="font-medium truncate">{svc.name}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-white/[0.06] text-muted-foreground">{svc.category}</span>
                    <span className="font-bold text-muted-foreground w-8 text-right">{svc.requests}</span>
                  </div>
                </div>
              )) : <div className="text-center py-6 text-muted-foreground text-xs">No SaaS services detected</div>}
            </div>
          </CardContent>
        </Card>

        <Card>
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
                    </Pie><Tooltip contentStyle={TOOLTIP_STYLE} /></PieChart>
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

        <Card>
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
                        <div className="h-full rounded-full progress-glow" style={{ width: `${(st.count / max) * 100}%`, backgroundColor: C[i % C.length] }} />
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

      {/* Domain Cloud + Top Blocked + Live Feed */}
      <div className="grid gap-3 lg:grid-cols-3">
        <Card>
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm">Top Domains</CardTitle></CardHeader>
          <CardContent className="p-2">
            {topDomains && topDomains.length > 0 ? (
              <div className="flex flex-wrap gap-1 max-h-[200px] overflow-y-auto custom-scrollbar">
                {topDomains.slice(0, 40).map((d, i) => {
                  const maxCount = topDomains[0].count;
                  const ratio = d.count / maxCount;
                  const size = Math.max(10, Math.min(20, 10 + ratio * 10));
                  const opacity = Math.max(0.4, ratio);
                  return (
                    <span
                      key={d.domain}
                      className="px-1.5 py-0.5 rounded cursor-default hover:bg-white/[0.04] transition-colors font-mono"
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

        <Card>
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm">Top Blocked</CardTitle></CardHeader>
          <CardContent className="p-2">
            <div className="space-y-1 max-h-[200px] overflow-y-auto custom-scrollbar">
              {s?.top_blocked?.map((item, i) => (
                <div key={i} className="flex items-center gap-2 py-1 text-xs row-hover rounded px-1">
                  <span className="text-muted-foreground w-4 text-right font-bold">{i + 1}</span>
                  <span className="font-mono truncate flex-1" title={item.dest}>{item.dest}</span>
                  <div className="w-12 bg-secondary h-1.5 rounded-full overflow-hidden shrink-0">
                    <div className="h-full bg-destructive rounded-full progress-glow glow-destructive" style={{ width: `${Math.min(100, (item.count / (s?.top_blocked?.[0]?.count || 1)) * 100)}%` }} />
                  </div>
                  <span className="font-bold text-destructive w-6 text-right">{item.count}</span>
                </div>
              ))}
              {(!s?.top_blocked?.length) && <div className="text-center py-8 text-muted-foreground text-xs">No blocked destinations</div>}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="p-3 pb-0"><CardTitle className="text-sm flex items-center gap-1.5"><Clock className="w-3.5 h-3.5 text-yellow-500" />Live Feed</CardTitle></CardHeader>
          <CardContent className="p-2">
            <div className="space-y-0.5 max-h-[200px] overflow-y-auto custom-scrollbar">
              {s?.recent_blocks?.map((b, i) => (
                <div key={i} className="flex items-center py-1 px-1 rounded row-hover text-xs">
                  <div className="relative w-1.5 h-1.5 mr-2 shrink-0">
                    <div className="w-1.5 h-1.5 rounded-full bg-destructive" />
                    <div className="absolute inset-0 w-1.5 h-1.5 rounded-full bg-destructive animate-status-ping" />
                  </div>
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

      <RegexPlayground />
    </div>
  );
}
