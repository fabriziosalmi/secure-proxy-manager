import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Users, RefreshCw, Search, X, Ban, Globe, Activity, Clock, ArrowUpDown,
} from 'lucide-react';
import { Card, CardContent } from '../components/ui/card';
import { IpBadge } from '../components/IpBadge';
import { api } from '../lib/api';
import type { ClientsData, ClientStat, ClientDetail } from '../types';

function parseUtc(ts: string): Date {
  return new Date(ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z');
}
function relative(ts: string): string {
  if (!ts) return '—';
  const d = parseUtc(ts).getTime();
  if (Number.isNaN(d)) return ts;
  const s = Math.max(0, Math.round((Date.now() - d) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}
function rate(blocked: number, total: number): number {
  return total > 0 ? Math.round((blocked / total) * 1000) / 10 : 0;
}

type SortKey = 'requests' | 'blocked' | 'rate';

// Declared at module scope (not inside render) so React keeps their identity
// stable — defining components during render resets their state every render
// and trips react-hooks/static-components.
function SortTh({ k, label, sort, onSort }: { k: SortKey; label: string; sort: SortKey; onSort: (k: SortKey) => void }) {
  return (
    <th className="px-5 py-3 font-medium">
      <button
        onClick={() => onSort(k)}
        className={`inline-flex items-center gap-1 hover:text-foreground transition-colors ${sort === k ? 'text-foreground' : ''}`}
      >
        {label}
        <ArrowUpDown className="w-3 h-3 opacity-60" />
      </button>
    </th>
  );
}

function Stat({ label, value, tone = '' }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="rounded-lg bg-white/[0.03] border border-white/[0.06] px-3 py-2.5">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">{label}</div>
      <div className={`text-lg font-semibold tabular-nums ${tone}`}>{value}</div>
    </div>
  );
}

export function Clients() {
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState<SortKey>('requests');
  const [selectedIp, setSelectedIp] = useState<string | null>(null);

  const { data, isLoading, isFetching, refetch } = useQuery<ClientsData>({
    queryKey: ['clients', 'statistics'],
    queryFn: () => api.get('clients/statistics').then((r) => r.data.data),
    refetchInterval: 30_000,
  });

  const clients: ClientStat[] = data?.clients ?? [];

  const rows = useMemo(() => {
    const t = search.trim().toLowerCase();
    const filtered = t ? clients.filter((c) => c.ip_address.toLowerCase().includes(t)) : clients;
    const sorted = [...filtered].sort((a, b) => {
      if (sort === 'blocked') return b.blocked - a.blocked;
      if (sort === 'rate') return rate(b.blocked, b.requests) - rate(a.blocked, a.requests);
      return b.requests - a.requests;
    });
    return sorted;
  }, [clients, search, sort]);

  return (
    <div className="page-enter space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <Users className="w-5 h-5 text-cyan-400" />
            Clients
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Source IPs seen by the proxy{typeof data?.total_clients === 'number' ? ` — ${data.total_clients} total` : ''}. Select a row for details.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium bg-white/[0.04] hover:bg-white/[0.08] transition-colors btn-press"
        >
          <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter by IP…"
          className="w-full pl-9 pr-3 py-2 rounded-lg bg-white/[0.03] border border-white/[0.08] text-sm focus:outline-none focus:border-cyan-500/40 focus:bg-white/[0.05] transition-colors"
        />
      </div>

      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-[10px] text-muted-foreground uppercase tracking-wider bg-white/[0.02] border-b border-white/[0.06]">
                <tr>
                  <th className="px-5 py-3 font-medium">Client IP</th>
                  <SortTh k="requests" label="Requests" sort={sort} onSort={setSort} />
                  <SortTh k="blocked" label="Blocked" sort={sort} onSort={setSort} />
                  <SortTh k="rate" label="Block rate" sort={sort} onSort={setSort} />
                  <th className="px-5 py-3 font-medium">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {isLoading ? (
                  <tr><td colSpan={5} className="px-5 py-10 text-center text-muted-foreground">Loading…</td></tr>
                ) : rows.length === 0 ? (
                  <tr><td colSpan={5} className="px-5 py-10 text-center text-muted-foreground">
                    {search ? 'No clients match the filter.' : 'No client traffic recorded yet.'}
                  </td></tr>
                ) : (
                  rows.map((c) => {
                    const br = rate(c.blocked, c.requests);
                    return (
                      <tr
                        key={c.ip_address}
                        onClick={() => setSelectedIp(c.ip_address)}
                        className="row-hover cursor-pointer"
                      >
                        <td className="px-5 py-3"><IpBadge ip={c.ip_address} /></td>
                        <td className="px-5 py-3 font-mono tabular-nums">{c.requests.toLocaleString()}</td>
                        <td className="px-5 py-3 font-mono tabular-nums">
                          {c.blocked > 0 ? <span className="text-orange-300">{c.blocked.toLocaleString()}</span> : <span className="text-muted-foreground">0</span>}
                        </td>
                        <td className="px-5 py-3">
                          <span className={`font-mono tabular-nums text-xs ${br >= 20 ? 'text-red-300' : br > 0 ? 'text-amber-300' : 'text-muted-foreground'}`}>
                            {br}%
                          </span>
                        </td>
                        <td className="px-5 py-3 text-xs text-muted-foreground whitespace-nowrap" title={c.last_seen ? parseUtc(c.last_seen).toLocaleString() : ''}>
                          {relative(c.last_seen)}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {selectedIp && <ClientDrawer ip={selectedIp} onClose={() => setSelectedIp(null)} />}
    </div>
  );
}

function ClientDrawer({ ip, onClose }: { ip: string; onClose: () => void }) {
  const { data, isLoading } = useQuery<ClientDetail>({
    queryKey: ['client-details', ip],
    queryFn: () => api.get(`clients/${encodeURIComponent(ip)}/details`).then((r) => r.data.data),
  });

  const br = data ? rate(data.blocked, data.total_requests) : 0;

  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md h-full overflow-y-auto bg-[var(--card)] border-l border-white/[0.08] shadow-2xl animate-in">
        <div className="sticky top-0 z-10 flex items-center justify-between px-5 py-4 border-b border-white/[0.06] bg-[var(--card)]">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <IpBadge ip={ip} />
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/[0.06] transition-colors" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>

        {isLoading || !data ? (
          <div className="p-8 text-center text-muted-foreground">Loading…</div>
        ) : (
          <div className="p-5 space-y-6">
            <div className="grid grid-cols-2 gap-3">
              <Stat label="Requests" value={data.total_requests.toLocaleString()} />
              <Stat label="Blocked" value={data.blocked.toLocaleString()} tone={data.blocked > 0 ? 'text-orange-300' : ''} />
              <Stat label="Block rate" value={`${br}%`} tone={br >= 20 ? 'text-red-300' : br > 0 ? 'text-amber-300' : ''} />
              <Stat label="Last seen" value={relative(data.last_seen)} />
            </div>
            <div className="text-xs text-muted-foreground flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" />
              First seen {data.first_seen ? parseUtc(data.first_seen).toLocaleString() : '—'}
            </div>

            <div>
              <h3 className="text-xs uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5" /> Top destinations
              </h3>
              {data.top_domains.length === 0 ? (
                <p className="text-sm text-muted-foreground">No destinations recorded.</p>
              ) : (
                <div className="space-y-1">
                  {data.top_domains.map((d) => (
                    <div key={d.destination} className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-white/[0.02] hover:bg-white/[0.04] transition-colors">
                      <span className="font-mono text-xs truncate" title={d.destination}>{d.destination}</span>
                      <span className="flex items-center gap-2 shrink-0 text-xs tabular-nums">
                        {d.blocked > 0 && (
                          <span className="inline-flex items-center gap-1 text-orange-300" title={`${d.blocked} blocked`}>
                            <Ban className="w-3 h-3" />{d.blocked}
                          </span>
                        )}
                        <span className="text-muted-foreground">{d.requests.toLocaleString()}</span>
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div>
              <h3 className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Recent requests</h3>
              {data.recent.length === 0 ? (
                <p className="text-sm text-muted-foreground">No recent requests.</p>
              ) : (
                <div className="space-y-1">
                  {data.recent.map((e, i) => {
                    const blocked = /DENIED|403|BLOCKED/i.test(e.status);
                    return (
                      <div key={i} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/[0.02] text-xs">
                        <span className="text-muted-foreground w-14 shrink-0" title={parseUtc(e.timestamp).toLocaleString()}>{relative(e.timestamp)}</span>
                        <span className="font-mono text-[10px] text-muted-foreground w-12 shrink-0">{e.method}</span>
                        <span className="font-mono truncate flex-1" title={e.destination}>{e.destination}</span>
                        <span className={`shrink-0 ${blocked ? 'text-orange-300' : 'text-muted-foreground'}`}>{blocked ? 'blocked' : 'ok'}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
