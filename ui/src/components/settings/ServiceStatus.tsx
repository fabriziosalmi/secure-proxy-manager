import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, Server, Tag, Users, ArrowDownUp, Ban, Database } from 'lucide-react';
import { Card, CardContent } from '../ui/card';
import { api, getData } from '../../lib/api';
import type { CacheStats, ClientsData } from '../../types';
import { formatCount } from '../../lib/format';
import { cacheCollected, cacheDisk, cacheHitPercent, cacheHitWindow } from '../../lib/cacheStats';
import { proxyAddress } from '../../lib/utils';
import { statusQuery } from '../../lib/queries';

// What a tile shows when it has no number: an ellipsis while the request is in
// flight, then "Not reported", never a bare placeholder that reads as a value.
function num(n: unknown, loading: boolean): string {
  if (typeof n === 'number') return formatCount(n);
  return loading ? '…' : 'Not reported';
}

function Tile({ icon: Icon, label, value, detail, tone = '', accent = false }: {
  icon: typeof Activity; label: string; value: ReactNode; detail?: string | null; tone?: string; accent?: boolean;
}) {
  return (
    <div className={`rounded-lg border px-3 py-2.5 ${accent ? 'border-cyan-500/20 bg-cyan-500/4' : 'border-border/50 bg-secondary/30'}`}>
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground mb-1">
        <Icon className="w-3 h-3" />
        {label}
      </div>
      <div className={`text-sm font-semibold tabular-nums truncate ${tone}`}>{value}</div>
      {/* The tile is narrow: the line is cut to fit and its title holds all of it. */}
      {detail && <div title={detail} className="mt-0.5 text-[11px] text-muted-foreground truncate">{detail}</div>}
    </div>
  );
}

/** The Cache hit tile: Squid's hit ratio when the proxy's record is current, and what there is otherwise. */
function cacheTile(cache: { data?: CacheStats | null; isLoading: boolean }): { value: string; detail: string | null } {
  const c = cache.data;
  switch (c?.state) {
    case 'current':
      return {
        value: cacheHitPercent(c) ?? 'Not measured yet',
        detail: [cacheHitPercent(c) === null ? "Squid's first minute" : cacheHitWindow(c), cacheDisk(c), cacheCollected(c)].filter(Boolean).join(' · '),
      };
    case 'stale':
      return { value: 'Out of date', detail: cacheCollected(c) };
    case 'not_collected':
      return { value: 'Not collected', detail: null };
    case 'unreadable':
      return { value: 'Not readable', detail: null };
    default:
      return { value: num(undefined, cache.isLoading), detail: null };
  }
}

export function ServiceStatus() {
  const opts = { refetchInterval: 15_000, staleTime: 10_000 };
  const status = useQuery({ ...statusQuery, ...opts });
  const summary = useQuery<{ today_blocked?: number }>({ queryKey: ['dash-summary-mini'], queryFn: () => getData('dashboard/summary'), ...opts });
  const cache = useQuery<CacheStats | null>({ queryKey: ['cache-mini'], queryFn: () => getData('cache/statistics'), ...opts });
  // A list endpoint: its count is in meta, beside data, so this one reads the
  // whole body. Unwrapping it left an array with no meta and the tile empty.
  const clients = useQuery<ClientsData | null>({ queryKey: ['clients-mini'], queryFn: () => api.get('clients/statistics').then((r) => r.data ?? null), ...opts });

  const s = status.data;
  const running = s?.proxy_status === 'running';
  const hit = cacheTile(cache);

  return (
    <Card>
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
              <span className={`text-sm font-semibold ${running ? 'text-emerald-600 dark:text-emerald-300' : 'text-red-600 dark:text-red-300'}`}>
                {status.isLoading ? '…' : running ? 'Running' : 'Offline'}
              </span>
            </div>
          </div>

          {/* Not proxy_host: that is the compose service name, which no client can reach. */}
          <Tile icon={Server} label="Listen" value={<span className="font-mono text-xs">{proxyAddress()}</span>} />
          <Tile icon={Tag} label="Version" value={s?.version ? `v${s.version}` : num(undefined, status.isLoading)} />
          <Tile icon={Users} label="Clients" value={num(clients.data?.meta?.total, clients.isLoading)} accent />
          <Tile icon={ArrowDownUp} label="Requests today" value={num(s?.requests_count, status.isLoading)} />
          <Tile icon={Ban} label="Blocked today" value={num(summary.data?.today_blocked, summary.isLoading)} tone={(summary.data?.today_blocked ?? 0) > 0 ? 'text-orange-600 dark:text-orange-300' : ''} />
          <Tile icon={Database} label="Cache hit" value={hit.value} detail={hit.detail} />
        </div>
      </CardContent>
    </Card>
  );
}
