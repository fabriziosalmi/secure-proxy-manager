import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, Server, Tag, Users, ArrowDownUp, Ban, Database } from 'lucide-react';
import { Card, CardContent } from '../ui/card';
import { api } from '../../lib/api';

// Unwrap the { status, data } envelope.
function api_get<T = unknown>(path: string): Promise<T> {
  return api.get(path).then((r) => r.data.data as T);
}

interface StatusData {
  proxy_status?: string;
  proxy_host?: string;
  proxy_port?: string;
  version?: string;
  requests_count?: number;
}

function num(n: unknown): string {
  return typeof n === 'number' ? n.toLocaleString() : '—';
}

function Tile({ icon: Icon, label, value, tone = '', accent = false }: {
  icon: typeof Activity; label: string; value: ReactNode; tone?: string; accent?: boolean;
}) {
  return (
    <div className={`rounded-lg border px-3 py-2.5 ${accent ? 'border-cyan-500/20 bg-cyan-500/[0.04]' : 'border-border/50 bg-secondary/30'}`}>
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground mb-1">
        <Icon className="w-3 h-3" />
        {label}
      </div>
      <div className={`text-sm font-semibold tabular-nums truncate ${tone}`}>{value}</div>
    </div>
  );
}

export function ServiceStatus() {
  const opts = { refetchInterval: 15_000, staleTime: 10_000 };
  const status = useQuery<StatusData>({ queryKey: ['status'], queryFn: () => api_get('status'), ...opts });
  const summary = useQuery<{ today_blocked?: number }>({ queryKey: ['dash-summary-mini'], queryFn: () => api_get('dashboard/summary'), ...opts });
  const cache = useQuery<{ hit_rate?: number }>({ queryKey: ['cache-mini'], queryFn: () => api_get('cache/statistics'), ...opts });
  const clients = useQuery<{ total_clients?: number }>({ queryKey: ['clients-mini'], queryFn: () => api_get('clients/statistics'), ...opts });

  const s = status.data;
  const running = s?.proxy_status === 'running';
  const hit = cache.data?.hit_rate;
  const hitPct = typeof hit === 'number' ? `${(hit <= 1 ? hit * 100 : hit).toFixed(1)}%` : '—';

  return (
    <Card className="bg-transparent">
      <CardContent className="p-4">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-3">
          <div className="rounded-lg border border-border/50 bg-secondary/30 px-3 py-2.5">
            <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground mb-1">
              <Activity className="w-3 h-3" /> Proxy
            </div>
            <div className="flex items-center gap-1.5">
              <span className={`relative flex h-2 w-2`}>
                {running && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400/70" />}
                <span className={`relative inline-flex rounded-full h-2 w-2 ${running ? 'bg-emerald-400' : 'bg-red-400'}`} />
              </span>
              <span className={`text-sm font-semibold ${running ? 'text-emerald-300' : 'text-red-300'}`}>
                {status.isLoading ? '…' : running ? 'Running' : 'Offline'}
              </span>
            </div>
          </div>

          <Tile icon={Server} label="Listen" value={<span className="font-mono text-xs">{s?.proxy_host ?? 'proxy'}:{s?.proxy_port ?? '3128'}</span>} />
          <Tile icon={Tag} label="Version" value={s?.version ? `v${s.version}` : '—'} />
          <Tile icon={Users} label="Clients" value={num(clients.data?.total_clients)} accent />
          <Tile icon={ArrowDownUp} label="Requests 24h" value={num(s?.requests_count)} />
          <Tile icon={Ban} label="Blocked 24h" value={num(summary.data?.today_blocked)} tone={(summary.data?.today_blocked ?? 0) > 0 ? 'text-orange-300' : ''} />
          <Tile icon={Database} label="Cache hit" value={hitPct} />
        </div>
      </CardContent>
    </Card>
  );
}
