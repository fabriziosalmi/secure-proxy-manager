import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Activity, Clock, ShieldCheck, Zap, Download, Copy, Check, Brain } from 'lucide-react';
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import React, { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import type { LogEntry, LogStats, TimelineEntry, SecurityScore, LogsPageData } from '../types';

const REFETCH_INTERVAL = 10_000;

export function Dashboard() {
  const [copied, setCopied] = useState(false);
  const proxyAddress = `${window.location.hostname}:3128`;

  const handleCopyProxy = () => {
    navigator.clipboard.writeText(proxyAddress).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  // Pause polling when tab is hidden
  const [visible, setVisible] = useState(document.visibilityState !== 'hidden');
  useEffect(() => {
    const handler = () => setVisible(document.visibilityState !== 'hidden');
    document.addEventListener('visibilitychange', handler);
    return () => document.removeEventListener('visibilitychange', handler);
  }, []);

  const { data: logStats } = useQuery<LogStats>({
    queryKey: ['logs', 'stats'],
    queryFn: () => api.get('logs/stats').then(r => r.data.data),
    refetchInterval: visible ? REFETCH_INTERVAL : false,
  });

  const { data: recentLogs } = useQuery<LogsPageData>({
    queryKey: ['logs', 'recent'],
    queryFn: () => api.get('logs?limit=5').then(r => r.data),
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
    refetchInterval: visible ? REFETCH_INTERVAL : false,
  });

  // Fetch cache stats to keep the backend warm (data not displayed)
  useQuery({
    queryKey: ['cache', 'statistics'],
    queryFn: () => api.get('cache/statistics'),
    refetchInterval: visible ? REFETCH_INTERVAL : false,
  });

  const { data: wafStats } = useQuery<{
    total_requests: number;
    total_blocked: number;
    block_rate_pct: number;
    avg_url_entropy: number;
    high_entropy_count: number;
    requests_last_minute: number;
    top_blocked_categories: { key: string; count: number }[];
  }>({
    queryKey: ['waf', 'stats'],
    queryFn: () => api.get('waf/stats').then(r => r.data.data),
    refetchInterval: visible ? REFETCH_INTERVAL : false,
  });

  const chartData = React.useMemo(() => {
    return timelineData || [
      { time: '13:43', total: 0, blocked: 0 }, { time: '14:43', total: 0, blocked: 0 },
      { time: '15:43', total: 0, blocked: 0 }, { time: '16:43', total: 0, blocked: 0 },
      { time: '17:43', total: 0, blocked: 0 }, { time: '18:43', total: 0, blocked: 0 },
      { time: '19:43', total: 0, blocked: 0 }, { time: '20:43', total: 0, blocked: 0 },
      { time: '21:43', total: 0, blocked: 0 }, { time: '22:43', total: 0, blocked: 0 },
      { time: '23:43', total: 0, blocked: 0 }, { time: '00:43', total: 0, blocked: 0 },
      { time: '01:43', total: 0, blocked: 0 }, { time: '02:43', total: 0, blocked: 0 },
      { time: '03:43', total: 0, blocked: 0 }, { time: '04:43', total: 0, blocked: 0 },
      { time: '05:43', total: 0, blocked: 0 }, { time: '06:43', total: 0, blocked: 0 },
      { time: '07:43', total: 0, blocked: 0 }, { time: '08:43', total: 0, blocked: 0 },
      { time: '09:43', total: 0, blocked: 0 }, { time: '10:43', total: 0, blocked: 0 },
      { time: '11:43', total: 0, blocked: 0 }, { time: '12:43', total: 0, blocked: 0 }
    ];
  }, [timelineData]);

  const logs = recentLogs?.data ?? recentLogs?.logs ?? ([] as LogEntry[]);

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground">Real-time overview of the proxy pipeline</p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => window.open('/api/analytics/report/pdf', '_blank')}
            className="flex items-center px-4 py-2 bg-secondary text-foreground hover:bg-secondary/80 rounded-md text-sm font-medium transition-colors"
          >
            <Download className="w-4 h-4 mr-2" />
            Export PDF Report
          </button>
        </div>
      </div>

      <Card className="bg-primary/5 border-primary/20">
        <CardContent className="py-3 px-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="text-sm text-muted-foreground">Configure your device to use this proxy:</div>
            <code className="text-sm font-mono font-semibold text-primary">{proxyAddress}</code>
          </div>
          <button
            type="button"
            onClick={handleCopyProxy}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-primary/10 hover:bg-primary/20 text-primary transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Total Requests</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{logStats?.total_count?.toLocaleString() || '0'}</div>
            <p className="text-xs text-muted-foreground mt-1">all time</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Security Score</CardTitle>
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{securityData?.score || 0}/100</div>
            <div className="w-full bg-secondary h-2 mt-2 rounded-full overflow-hidden">
              <div
                className={`h-full ${
                  (securityData?.score || 0) > 80 ? 'bg-emerald-500' :
                  (securityData?.score || 0) > 50 ? 'bg-yellow-500' : 'bg-destructive'
                }`}
                style={{ width: `${securityData?.score || 0}%` }}
              ></div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Direct IP Blocks</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{logStats?.ip_blocks_count?.toLocaleString() || '0'}</div>
            <p className="text-xs text-muted-foreground mt-1">by IP address rules</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Blocked Threats</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-destructive">{logStats?.blocked_count?.toLocaleString() || '0'}</div>
            <p className="text-xs text-destructive/80 mt-1">requests denied</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-7">
        <Card className="col-span-4 bg-card/50">
          <CardHeader>
            <CardTitle>Traffic - 24h</CardTitle>
            <p className="text-sm text-muted-foreground">Proxy requests and blocked attempts</p>
          </CardHeader>
          <CardContent className="pl-0">
            <div className="h-[300px] w-full">
              <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
                <AreaChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
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
                  <XAxis
                    dataKey="time"
                    stroke="#888888"
                    fontSize={12}
                    tickLine={false}
                    axisLine={false}
                    tick={{ fill: '#64748b' }}
                  />
                  <YAxis
                    stroke="#888888"
                    fontSize={12}
                    tickLine={false}
                    axisLine={false}
                    tick={{ fill: '#64748b' }}
                  />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px' }}
                    itemStyle={{ color: '#e2e8f0' }}
                  />
                  <Area type="monotone" dataKey="total" name="Total Requests" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorTotal)" />
                  <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorBlocked)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card className="col-span-3 bg-card/50 overflow-hidden flex flex-col">
          <CardHeader>
            <CardTitle>Recent Sessions</CardTitle>
            <p className="text-sm text-muted-foreground">Last proxy attempts</p>
          </CardHeader>
          <CardContent className="flex-1 overflow-y-auto">
            <div className="space-y-4">
              {logs.map((log, i: number) => (
                <div key={i} className="flex items-center justify-between border-b border-border/50 pb-4 last:border-0 last:pb-0">
                  <div className="space-y-1 overflow-hidden pr-4">
                    <p className="text-sm font-medium leading-none truncate" title={log.destination}>
                      {log.destination}
                    </p>
                    <p className="text-xs text-muted-foreground">{new Date(log.timestamp).toLocaleTimeString()}</p>
                  </div>
                  <div className="flex items-center gap-4 shrink-0">
                    <div className="text-sm text-muted-foreground">{log.method}</div>
                    <div className={`px-2.5 py-0.5 rounded-full text-xs font-medium border ${
                      log.status?.includes('DENIED')
                        ? 'bg-destructive/10 text-destructive border-destructive/20'
                        : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                    }`}>
                      {log.status?.includes('DENIED') ? 'Blocked' : 'Success'}
                    </div>
                  </div>
                </div>
              ))}
              {logs.length === 0 && (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  No recent logs available.
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* WAF Intelligence */}
      {wafStats && (
        <Card className="bg-card/50">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Brain className="h-5 w-5 text-primary" />
              <CardTitle>WAF Intelligence</CardTitle>
            </div>
            <p className="text-sm text-muted-foreground">Real-time traffic analysis from 171 rules</p>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase">Req/min</p>
                <p className="text-2xl font-bold">{wafStats.requests_last_minute}</p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase">Block Rate</p>
                <p className="text-2xl font-bold text-destructive">{wafStats.block_rate_pct}%</p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase">Avg URL Entropy</p>
                <p className="text-2xl font-bold">{wafStats.avg_url_entropy}</p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase">High Entropy</p>
                <p className={`text-2xl font-bold ${wafStats.high_entropy_count > 0 ? 'text-yellow-500' : ''}`}>{wafStats.high_entropy_count}</p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase">WAF Inspected</p>
                <p className="text-2xl font-bold">{wafStats.total_requests.toLocaleString()}</p>
              </div>
            </div>
            {wafStats.top_blocked_categories.length > 0 && (
              <div className="mt-4 pt-4 border-t border-border/50">
                <p className="text-xs text-muted-foreground uppercase mb-2">Top Blocked Categories</p>
                <div className="flex flex-wrap gap-2">
                  {wafStats.top_blocked_categories.slice(0, 5).map((cat) => (
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
    </div>
  );
}
