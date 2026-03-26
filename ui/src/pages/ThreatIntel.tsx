import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Shield, Activity, Globe, AlertTriangle, Clock, TrendingUp } from 'lucide-react';
import { BarChart, Bar, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell, AreaChart, Area } from 'recharts';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useEffect, useState } from 'react';
import type { TimelineEntry } from '../types';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#ec4899'];

export function ThreatIntel() {
  const [visible, setVisible] = useState(document.visibilityState !== 'hidden');
  useEffect(() => {
    const h = () => setVisible(document.visibilityState !== 'hidden');
    document.addEventListener('visibilitychange', h);
    return () => document.removeEventListener('visibilitychange', h);
  }, []);

  const { data: summary } = useQuery<{
    total_requests: number;
    blocked_requests: number;
    today_blocked: number;
    top_blocked: { dest: string; count: number }[];
    top_clients: { ip: string; count: number }[];
    threat_categories: { category: string; count: number }[];
    recent_blocks: { timestamp: string; source_ip: string; method: string; destination: string; status: string }[];
    waf: { total_blocked: number; top_blocked_categories: { key: string; count: number }[] } | null;
  }>({
    queryKey: ['dashboard', 'summary'],
    queryFn: () => api.get('dashboard/summary').then(r => r.data.data),
    refetchInterval: visible ? 15_000 : false,
  });

  const { data: timeline } = useQuery<TimelineEntry[]>({
    queryKey: ['logs', 'timeline'],
    queryFn: () => api.get('logs/timeline?hours=72').then(r => r.data.data),
    refetchInterval: visible ? 30_000 : false,
  });

  const wafCats = summary?.waf?.top_blocked_categories ?? [];
  const totalBlocked = summary?.blocked_requests ?? 0;
  const todayBlocked = summary?.today_blocked ?? 0;

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Threat Intelligence</h1>
        <p className="text-muted-foreground">Security analytics and threat visibility</p>
      </div>

      {/* Key metrics */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card className="bg-card/50 border-destructive/20">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase">Today's Blocks</p>
                <p className="text-3xl font-bold text-destructive">{todayBlocked.toLocaleString()}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-destructive/40" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase">Total Blocks</p>
                <p className="text-3xl font-bold">{totalBlocked.toLocaleString()}</p>
              </div>
              <Shield className="w-8 h-8 text-primary/40" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase">WAF Blocks</p>
                <p className="text-3xl font-bold text-orange-500">{summary?.waf?.total_blocked ?? 0}</p>
              </div>
              <Activity className="w-8 h-8 text-orange-500/40" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase">Attack Categories</p>
                <p className="text-3xl font-bold">{wafCats.length}</p>
              </div>
              <Globe className="w-8 h-8 text-muted-foreground/40" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Threat timeline (72h) */}
      <Card className="bg-card/50">
        <CardHeader>
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-primary" />
            <CardTitle>Threat Timeline (72h)</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="h-[250px]">
            <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
              <AreaChart data={timeline ?? []} margin={{ top: 5, right: 20, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="blockGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#888" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis stroke="#888" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#ef4444" strokeWidth={2} fill="url(#blockGrad)" />
                <Area type="monotone" dataKey="total" name="Total" stroke="#3b82f6" strokeWidth={1} fill="none" opacity={0.5} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* WAF categories + Top blocked side by side */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card className="bg-card/50">
          <CardHeader>
            <CardTitle>WAF Block Categories</CardTitle>
          </CardHeader>
          <CardContent>
            {wafCats.length > 0 ? (
              <div className="h-[250px]">
                <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                  <BarChart data={wafCats.slice(0, 10)} layout="vertical" margin={{ left: 100 }}>
                    <XAxis type="number" stroke="#888" fontSize={10} tickLine={false} />
                    <YAxis type="category" dataKey="key" stroke="#888" fontSize={10} tickLine={false} width={100} />
                    <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px' }} />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {wafCats.slice(0, 10).map((_, i) => (
                        <Cell key={i} fill={COLORS[i % COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-[250px] flex items-center justify-center text-muted-foreground text-sm">No WAF blocks recorded</div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader>
            <CardTitle>Top Blocked Destinations</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-[300px] overflow-y-auto">
              {summary?.top_blocked?.map((item, i) => (
                <div key={i} className="flex items-center gap-3 py-2 border-b border-border/20 last:border-0">
                  <span className="text-xs font-bold text-muted-foreground w-6">{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-mono truncate" title={item.dest}>{item.dest}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <div className="w-16 bg-secondary h-2 rounded-full overflow-hidden">
                      <div className="h-full bg-destructive rounded-full" style={{ width: `${Math.min(100, (item.count / (summary?.top_blocked?.[0]?.count || 1)) * 100)}%` }} />
                    </div>
                    <span className="text-sm font-bold text-destructive w-10 text-right">{item.count}</span>
                  </div>
                </div>
              ))}
              {(!summary?.top_blocked || summary.top_blocked.length === 0) && (
                <div className="text-center py-8 text-muted-foreground text-sm">No blocked destinations</div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent threat feed */}
      <Card className="bg-card/50">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-yellow-500" />
            <CardTitle>Live Threat Feed</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-1">
            {summary?.recent_blocks?.map((block, i) => (
              <div key={i} className="flex items-center py-2 px-3 rounded-md hover:bg-secondary/20 transition-colors">
                <div className="w-2 h-2 rounded-full bg-destructive mr-3 shrink-0 animate-pulse" />
                <span className="text-xs text-muted-foreground w-20 shrink-0 font-mono">{new Date(block.timestamp).toLocaleTimeString()}</span>
                <span className="text-xs text-muted-foreground w-28 shrink-0 font-mono">{block.source_ip}</span>
                <span className="text-xs w-14 shrink-0 font-mono text-primary">{block.method || '-'}</span>
                <span className="text-sm truncate flex-1 font-mono" title={block.destination}>{block.destination}</span>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium shrink-0 ml-2 ${
                  block.status?.includes('403') ? 'bg-destructive/10 text-destructive border border-destructive/20' :
                  'bg-orange-500/10 text-orange-500 border border-orange-500/20'
                }`}>
                  {block.status?.includes('403') ? 'WAF' : 'DENIED'}
                </span>
              </div>
            ))}
            {(!summary?.recent_blocks || summary.recent_blocks.length === 0) && (
              <div className="text-center py-8 text-muted-foreground text-sm">No threats detected</div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Top clients */}
      {summary?.top_clients && summary.top_clients.length > 0 && (
        <Card className="bg-card/50">
          <CardHeader>
            <CardTitle>Top Active Clients</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {summary.top_clients.map((client, i) => (
                <div key={i} className="p-3 bg-secondary/30 rounded-lg text-center">
                  <p className="text-sm font-mono font-semibold">{client.ip}</p>
                  <p className="text-2xl font-bold text-primary mt-1">{client.count}</p>
                  <p className="text-xs text-muted-foreground">requests</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
