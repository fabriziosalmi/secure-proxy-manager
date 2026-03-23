import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Activity, Clock, ShieldCheck, Zap } from 'lucide-react';
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { useApi } from '../hooks/useApi';

export function Dashboard() {
  const { data: cacheStats } = useApi<any>('cache/statistics');
  const { data: logStats } = useApi<any>('logs/stats');
  const { data: recentLogs } = useApi<any>('logs?limit=5');

  // Format chart data based on some mock history since backend doesn't provide timeline yet
  const chartData = [
    { time: '13:43', rate: 0 }, { time: '14:43', rate: 0 }, { time: '15:43', rate: 0 },
    { time: '16:43', rate: 0 }, { time: '17:43', rate: 0 }, { time: '18:43', rate: 0 },
    { time: '19:43', rate: 0 }, { time: '20:43', rate: 0 }, { time: '21:43', rate: 0 },
    { time: '22:43', rate: 0 }, { time: '23:43', rate: 0 }, { time: '00:43', rate: 0 },
    { time: '01:43', rate: 0 }, { time: '02:43', rate: 0 }, { time: '03:43', rate: 0 },
    { time: '04:43', rate: 0 }, { time: '05:43', rate: 0 }, { time: '06:43', rate: 0 },
    { time: '07:43', rate: 0 }, { time: '08:43', rate: 0 }, { time: '09:43', rate: 0 },
    { time: '10:43', rate: 0 }, { time: '11:43', rate: 0 }, 
    { time: '12:43', rate: cacheStats?.hit_ratio || 0 },
  ];

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">Real-time overview of the proxy pipeline</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Total Requests</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{logStats?.total_logs?.toLocaleString() || '0'}</div>
            <p className="text-xs text-muted-foreground mt-1">all time</p>
          </CardContent>
        </Card>
        
        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Cache Hit Rate</CardTitle>
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{cacheStats?.hit_ratio?.toFixed(1) || '0.0'}%</div>
            <p className="text-xs text-emerald-500 mt-1">cache performance</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Avg Response</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{cacheStats?.avg_response_time || 'N/A'}s</div>
            <p className="text-xs text-muted-foreground mt-1">estimated duration</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium uppercase text-muted-foreground">Blocked Threats</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-destructive">{logStats?.blocked_requests?.toLocaleString() || '0'}</div>
            <p className="text-xs text-destructive/80 mt-1">requests denied</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-7">
        <Card className="col-span-4 bg-card/50">
          <CardHeader>
            <CardTitle>Cache Hit Rate - 24 h</CardTitle>
            <p className="text-sm text-muted-foreground">Rolling proxy success rate per hour</p>
          </CardHeader>
          <CardContent className="pl-0">
            <div className="h-[300px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorRate" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
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
                    tickFormatter={(value) => `${value}%`}
                    tick={{ fill: '#64748b' }}
                  />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px' }}
                    itemStyle={{ color: '#e2e8f0' }}
                  />
                  <Area
                    type="monotone"
                    dataKey="rate"
                    stroke="#3b82f6"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorRate)"
                  />
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
              {(recentLogs?.logs || []).map((log: any, i: number) => (
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
                      log.status.includes('DENIED') 
                        ? 'bg-destructive/10 text-destructive border-destructive/20' 
                        : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                    }`}>
                      {log.status.includes('DENIED') ? 'Blocked' : 'Success'}
                    </div>
                  </div>
                </div>
              ))}
              {(!recentLogs || recentLogs.logs?.length === 0) && (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  No recent logs available.
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}