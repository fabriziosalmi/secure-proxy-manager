import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Activity, ShieldCheck, Zap, Download, Copy, Check, Brain, Shield, Globe, AlertTriangle, TrendingUp } from 'lucide-react';
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell, PieChart, Pie } from 'recharts';
import React, { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import type { TimelineEntry, SecurityScore } from '../types';

const REFETCH_INTERVAL = 10_000;
const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#ec4899'];

export function Dashboard() {
  const [copied, setCopied] = useState(false);
  const proxyAddress = `${window.location.hostname}:3128`;

  const handleCopyProxy = () => {
    navigator.clipboard.writeText(proxyAddress).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const [visible, setVisible] = useState(document.visibilityState !== 'hidden');
  useEffect(() => {
    const handler = () => setVisible(document.visibilityState !== 'hidden');
    document.addEventListener('visibilitychange', handler);
    return () => document.removeEventListener('visibilitychange', handler);
  }, []);

  // Single aggregated endpoint for all dashboard data
  const { data: summary } = useQuery<{
    total_requests: number;
    blocked_requests: number;
    today_requests: number;
    today_blocked: number;
    top_blocked: { dest: string; count: number }[];
    top_clients: { ip: string; count: number }[];
    threat_categories: { category: string; count: number }[];
    ip_blacklist_count: number;
    domain_blacklist_count: number;
    recent_blocks: { timestamp: string; source_ip: string; method: string; destination: string; status: string }[];
    waf: { total_requests: number; total_blocked: number; block_rate_pct: number; avg_url_entropy: number; high_entropy_count: number; requests_last_minute: number; top_blocked_categories: { key: string; count: number }[] } | null;
  }>({
    queryKey: ['dashboard', 'summary'],
    queryFn: () => api.get('dashboard/summary').then(r => r.data.data),
    refetchInterval: visible ? REFETCH_INTERVAL : false,
  });

  const { data: timelineData } = useQuery<TimelineEntry[]>({
    queryKey: ['logs', 'timeline'],
    queryFn: () => api.get('logs/timeline').then(r => r.data.data),
    refetchInterval: visible ? REFETCH_INTERVAL : false,
  });

  const { data: securityData } = useQuery<SecurityScore>({
    queryKey: ['security', 'score'],
    queryFn: () => api.get('security/score').then(r => r.data.data),
    refetchInterval: visible ? 30_000 : false,
  });

  const chartData = React.useMemo(() => timelineData ?? [], [timelineData]);
  const blockRate = summary?.total_requests ? ((summary.blocked_requests / summary.total_requests) * 100).toFixed(1) : '0';
  const waf = summary?.waf;

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground">Real-time overview of the proxy pipeline</p>
        </div>
        <div className="flex gap-2">
          <button type="button" onClick={() => window.open('/api/analytics/report/pdf', '_blank')}
            className="flex items-center px-4 py-2 bg-secondary text-foreground hover:bg-secondary/80 rounded-md text-sm font-medium transition-colors">
            <Download className="w-4 h-4 mr-2" />Export PDF
          </button>
        </div>
      </div>

      {/* Proxy address */}
      <Card className="bg-primary/5 border-primary/20">
        <CardContent className="py-3 px-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="text-sm text-muted-foreground">Configure your device to use this proxy:</div>
            <code className="text-sm font-mono font-semibold text-primary">{proxyAddress}</code>
          </div>
          <button type="button" onClick={handleCopyProxy}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-primary/10 hover:bg-primary/20 text-primary transition-colors">
            {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </CardContent>
      </Card>

      {/* Stats row */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Today</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{(summary?.today_requests ?? 0).toLocaleString()}</div>
            <p className="text-xs text-muted-foreground mt-1">{summary?.today_blocked ?? 0} blocked</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Total</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{(summary?.total_requests ?? 0).toLocaleString()}</div>
            <p className="text-xs text-muted-foreground mt-1">all time</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Block Rate</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-3xl font-bold ${parseFloat(blockRate) > 50 ? 'text-destructive' : parseFloat(blockRate) > 10 ? 'text-yellow-500' : 'text-emerald-500'}`}>{blockRate}%</div>
            <p className="text-xs text-muted-foreground mt-1">{(summary?.blocked_requests ?? 0).toLocaleString()} blocked</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Score</CardTitle>
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{securityData?.score || 0}/100</div>
            <div className="w-full bg-secondary h-2 mt-2 rounded-full overflow-hidden">
              <div className={`h-full ${(securityData?.score || 0) > 80 ? 'bg-emerald-500' : (securityData?.score || 0) > 50 ? 'bg-yellow-500' : 'bg-destructive'}`}
                style={{ width: `${securityData?.score || 0}%` }} />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Rules</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-xl font-bold">{(summary?.ip_blacklist_count ?? 0).toLocaleString()} IPs</div>
            <p className="text-xs text-muted-foreground mt-1">{(summary?.domain_blacklist_count ?? 0).toLocaleString()} domains</p>
          </CardContent>
        </Card>
      </div>

      {/* Traffic chart + Threat categories */}
      <div className="grid gap-4 md:grid-cols-7">
        <Card className="col-span-4 bg-card/50">
          <CardHeader>
            <CardTitle>Traffic - 24h</CardTitle>
          </CardHeader>
          <CardContent className="pl-0">
            <div className="h-[280px] w-full">
              <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                <AreaChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#888" fontSize={11} tickLine={false} axisLine={false} tick={{ fill: '#64748b' }} />
                  <YAxis stroke="#888" fontSize={11} tickLine={false} axisLine={false} tick={{ fill: '#64748b' }} />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px' }} itemStyle={{ color: '#e2e8f0' }} />
                  <Area type="monotone" dataKey="total" name="Total" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorTotal)" />
                  <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorBlocked)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card className="col-span-3 bg-card/50">
          <CardHeader>
            <CardTitle>Threat Categories</CardTitle>
          </CardHeader>
          <CardContent>
            {summary?.threat_categories && summary.threat_categories.length > 0 ? (
              <div className="h-[200px]">
                <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                  <PieChart>
                    <Pie data={summary.threat_categories} dataKey="count" nameKey="category" cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3}>
                      {summary.threat_categories.map((_, i) => (
                        <Cell key={i} fill={COLORS[i % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px' }} itemStyle={{ color: '#e2e8f0' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-[200px] flex items-center justify-center text-muted-foreground text-sm">No threats detected</div>
            )}
            <div className="flex flex-wrap gap-2 mt-2">
              {summary?.threat_categories?.map((cat, i) => (
                <span key={cat.category} className="text-xs px-2 py-1 rounded-full border" style={{ borderColor: COLORS[i % COLORS.length] + '40', color: COLORS[i % COLORS.length] }}>
                  {cat.category} ({cat.count})
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Top blocked + Recent blocks */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card className="bg-card/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-destructive" />
              Top Blocked (24h)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {summary?.top_blocked?.slice(0, 8).map((item, i) => (
                <div key={i} className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0">
                  <span className="text-sm truncate max-w-[300px] text-muted-foreground font-mono" title={item.dest}>{item.dest}</span>
                  <span className="text-sm font-semibold text-destructive ml-2 shrink-0">{item.count}</span>
                </div>
              ))}
              {(!summary?.top_blocked || summary.top_blocked.length === 0) && (
                <div className="text-center py-4 text-muted-foreground text-sm">No blocks in the last 24h</div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-yellow-500" />
              Recent Blocks
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {summary?.recent_blocks?.slice(0, 8).map((block, i) => (
                <div key={i} className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0">
                  <div className="overflow-hidden mr-2">
                    <p className="text-sm truncate max-w-[250px] font-mono" title={block.destination}>{block.destination}</p>
                    <p className="text-xs text-muted-foreground">{block.source_ip} - {new Date(block.timestamp).toLocaleTimeString()}</p>
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium shrink-0 ${
                    block.status?.includes('403') ? 'bg-destructive/10 text-destructive border border-destructive/20' :
                    'bg-orange-500/10 text-orange-500 border border-orange-500/20'
                  }`}>
                    {block.status?.includes('403') ? 'WAF' : 'DENIED'}
                  </span>
                </div>
              ))}
              {(!summary?.recent_blocks || summary.recent_blocks.length === 0) && (
                <div className="text-center py-4 text-muted-foreground text-sm">No recent blocks</div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* WAF Intelligence */}
      {waf && (
        <Card className="bg-card/50">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Brain className="h-5 w-5 text-primary" />
              <CardTitle>WAF Intelligence</CardTitle>
            </div>
            <p className="text-sm text-muted-foreground">Real-time traffic analysis — 166 rules + 5 behavioral heuristics</p>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase">Req/min</p>
                <p className="text-2xl font-bold">{waf.requests_last_minute}</p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase">WAF Inspected</p>
                <p className="text-2xl font-bold">{waf.total_requests.toLocaleString()}</p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase">WAF Blocked</p>
                <p className="text-2xl font-bold text-destructive">{waf.total_blocked}</p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase">Block Rate</p>
                <p className={`text-2xl font-bold ${waf.block_rate_pct > 10 ? 'text-destructive' : 'text-emerald-500'}`}>{waf.block_rate_pct}%</p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase">Avg Entropy</p>
                <p className="text-2xl font-bold">{waf.avg_url_entropy}</p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase">High Entropy</p>
                <p className={`text-2xl font-bold ${waf.high_entropy_count > 0 ? 'text-yellow-500' : ''}`}>{waf.high_entropy_count}</p>
              </div>
            </div>
            {waf.top_blocked_categories.length > 0 && (
              <div className="mt-4 pt-4 border-t border-border/50">
                <p className="text-xs text-muted-foreground uppercase mb-2">Top Blocked Categories</p>
                <div className="flex flex-wrap gap-2">
                  {waf.top_blocked_categories.slice(0, 8).map((cat) => (
                    <span key={cat.key} className="px-2.5 py-1 rounded-full text-xs font-medium bg-destructive/10 text-destructive border border-destructive/20">
                      {cat.key} ({cat.count})
                    </span>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Top Clients */}
      {summary?.top_clients && summary.top_clients.length > 0 && (
        <Card className="bg-card/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-primary" />
              Top Clients (24h)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {summary.top_clients.slice(0, 10).map((client, i) => (
                <div key={i} className="flex items-center justify-between p-2 bg-secondary/30 rounded-md">
                  <span className="text-sm font-mono text-muted-foreground">{client.ip}</span>
                  <span className="text-sm font-bold ml-2">{client.count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
