import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ScrollText, RefreshCw, Search, Download, ChevronLeft, ChevronRight,
  LogIn, LogOut, ShieldAlert, KeyRound, Plus, Trash2, Settings2, Database, RotateCcw,
} from 'lucide-react';
import { Card, CardContent } from '../components/ui/card';
import { IpBadge } from '../components/IpBadge';
import { api } from '../lib/api';
import type { AuditEntry, AuditPageData } from '../types';

const PAGE_SIZE = 50;

// Visual treatment per action. Colour only — never used to move the row.
function actionStyle(action: string): { label: string; cls: string; Icon: typeof LogIn } {
  const a = action.toLowerCase();
  if (a === 'login') return { label: 'Login', cls: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/20', Icon: LogIn };
  if (a === 'login_failed') return { label: 'Login failed', cls: 'text-red-300 bg-red-500/10 border-red-500/25', Icon: ShieldAlert };
  if (a === 'logout') return { label: 'Logout', cls: 'text-slate-300 bg-white/[0.04] border-white/10', Icon: LogOut };
  if (a === 'change_password') return { label: 'Password change', cls: 'text-amber-300 bg-amber-500/10 border-amber-500/20', Icon: KeyRound };
  if (a.startsWith('add_')) return { label: action.replace(/_/g, ' '), cls: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/20', Icon: Plus };
  if (a.startsWith('delete_') || a.includes('remove')) return { label: action.replace(/_/g, ' '), cls: 'text-orange-300 bg-orange-500/10 border-orange-500/20', Icon: Trash2 };
  if (a.startsWith('update_set')) return { label: action.replace(/_/g, ' '), cls: 'text-cyan-300 bg-cyan-500/10 border-cyan-500/20', Icon: Settings2 };
  if (a === 'database_reset') return { label: 'Database reset', cls: 'text-red-300 bg-red-500/10 border-red-500/25', Icon: Database };
  if (a.includes('config') || a.includes('cache') || a.includes('clear') || a.includes('restore') || a.includes('reload'))
    return { label: action.replace(/_/g, ' '), cls: 'text-blue-300 bg-blue-500/10 border-blue-500/20', Icon: RotateCcw };
  return { label: action.replace(/_/g, ' '), cls: 'text-slate-300 bg-white/[0.04] border-white/10', Icon: ScrollText };
}

function parseUtc(ts: string): Date {
  // Backend stores `datetime('now')` → "2026-06-04 14:30:00" (UTC, no tz).
  return new Date(ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z');
}

function relative(ts: string): string {
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

export function Audit() {
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState('');

  const { data, isLoading, isFetching, refetch } = useQuery<AuditPageData>({
    queryKey: ['audit-log', offset],
    queryFn: () => api.get(`audit-log?limit=${PAGE_SIZE}&offset=${offset}`).then((r) => r.data),
    refetchInterval: 30_000,
  });

  const entries: AuditEntry[] = data?.data ?? [];
  const total = data?.total ?? 0;

  const filtered = useMemo(() => {
    const t = search.trim().toLowerCase();
    if (!t) return entries;
    return entries.filter((e) =>
      [e.username, e.action, e.target, e.details].some((f) => (f ?? '').toLowerCase().includes(t)),
    );
  }, [entries, search]);

  const exportCsv = () => {
    const rows = [
      ['timestamp', 'username', 'action', 'target', 'details'],
      ...filtered.map((e) => [e.timestamp, e.username ?? '', e.action, e.target ?? '', e.details ?? '']),
    ];
    const csv = rows
      .map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const from = total === 0 ? 0 : offset + 1;
  const to = offset + entries.length;

  return (
    <div className="page-enter space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <ScrollText className="w-5 h-5 text-cyan-400" />
            Audit Log
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Administrative actions — logins, blacklist and settings changes, maintenance.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium bg-white/[0.04] hover:bg-white/[0.08] transition-colors btn-press"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={exportCsv}
            disabled={filtered.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium bg-white/[0.04] hover:bg-white/[0.08] transition-colors btn-press disabled:opacity-40 disabled:pointer-events-none"
          >
            <Download className="w-4 h-4" />
            CSV
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter this page by user, action, target…"
          className="w-full pl-9 pr-3 py-2 rounded-lg bg-white/[0.03] border border-white/[0.08] text-sm focus:outline-none focus:border-cyan-500/40 focus:bg-white/[0.05] transition-colors"
        />
      </div>

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-[10px] text-muted-foreground uppercase tracking-wider bg-white/[0.02] border-b border-white/[0.06]">
                <tr>
                  <th className="px-5 py-3 font-medium">Time</th>
                  <th className="px-5 py-3 font-medium">User</th>
                  <th className="px-5 py-3 font-medium">Action</th>
                  <th className="px-5 py-3 font-medium">Target</th>
                  <th className="px-5 py-3 font-medium">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {isLoading ? (
                  <tr><td colSpan={5} className="px-5 py-10 text-center text-muted-foreground">Loading…</td></tr>
                ) : filtered.length === 0 ? (
                  <tr><td colSpan={5} className="px-5 py-10 text-center text-muted-foreground">
                    {search ? 'No entries match the filter.' : 'No audit events recorded yet.'}
                  </td></tr>
                ) : (
                  filtered.map((e) => {
                    const { label, cls, Icon } = actionStyle(e.action);
                    const targetIsIp = /^\d{1,3}(\.\d{1,3}){3}/.test(e.target ?? '');
                    return (
                      <tr key={e.id} className="row-hover align-top">
                        <td className="px-5 py-3 whitespace-nowrap">
                          <span className="text-foreground" title={parseUtc(e.timestamp).toLocaleString()}>
                            {relative(e.timestamp)}
                          </span>
                        </td>
                        <td className="px-5 py-3 whitespace-nowrap font-mono text-xs text-foreground">
                          {e.username || <span className="text-muted-foreground">—</span>}
                        </td>
                        <td className="px-5 py-3 whitespace-nowrap">
                          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md border text-xs font-medium ${cls}`}>
                            <Icon className="w-3.5 h-3.5" />
                            {label}
                          </span>
                        </td>
                        <td className="px-5 py-3 font-mono text-xs text-muted-foreground max-w-[22rem] truncate" title={e.target ?? ''}>
                          {e.target ? (targetIsIp ? <IpBadge ip={e.target} /> : e.target) : <span className="text-muted-foreground/50">—</span>}
                        </td>
                        <td className="px-5 py-3 text-xs text-muted-foreground max-w-[24rem] truncate" title={e.details ?? ''}>
                          {e.details || <span className="text-muted-foreground/50">—</span>}
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

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">
          {total === 0 ? 'No entries' : `Showing ${from}–${to} of ${total}`}
          {search && entries.length !== filtered.length ? ` · ${filtered.length} match filter` : ''}
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
            disabled={offset === 0}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] transition-colors btn-press disabled:opacity-40 disabled:pointer-events-none"
          >
            <ChevronLeft className="w-4 h-4" /> Prev
          </button>
          <button
            onClick={() => setOffset((o) => o + PAGE_SIZE)}
            disabled={to >= total}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] transition-colors btn-press disabled:opacity-40 disabled:pointer-events-none"
          >
            Next <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
