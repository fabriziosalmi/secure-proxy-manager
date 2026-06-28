import { Card, CardContent } from '../components/ui/card';
import { api, getErrorMessage } from '../lib/api';
import { isValidIP, isValidDomain } from '../lib/validation';
import type { EgressEntry } from '../types';
import { ArrowUpFromLine, Plus, Trash2, Globe, Network, ShieldCheck } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

const PAGE_SIZE = 50;

export function EgressAllowlist() {
  const queryClient = useQueryClient();
  const [newItem, setNewItem] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [pendingDeleteId, setPendingDeleteId] = useState<number | null>(null);

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  const { data: result } = useQuery<{ data: EgressEntry[]; total: number }>({
    queryKey: ['egress-allowlist', page, search],
    queryFn: () => api
      .get(`egress-allowlist?limit=${PAGE_SIZE}&offset=${page * PAGE_SIZE}&search=${encodeURIComponent(search)}`)
      .then(r => ({ data: r.data.data, total: r.data.total })),
  });
  const entries = result?.data ?? [];
  const total = result?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['egress-allowlist'] });

  const addMutation = useMutation({
    mutationFn: (payload: { entry: string; description: string }) => api.post('egress-allowlist', payload),
    onSuccess: () => {
      if (!mountedRef.current) return;
      toast.success('Entry added to egress allowlist');
      setNewItem('');
      setNewDesc('');
      invalidate();
    },
    onError: (err) => { if (mountedRef.current) toast.error(getErrorMessage(err, 'Failed to add entry')); },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.delete(`egress-allowlist/${id}`),
    onSuccess: () => {
      if (!mountedRef.current) return;
      toast.success('Entry removed');
      setPendingDeleteId(null);
      invalidate();
    },
    onError: (err) => { if (mountedRef.current) toast.error(getErrorMessage(err, 'Failed to remove entry')); },
  });

  const handleAdd = () => {
    const v = newItem.trim().toLowerCase();
    if (!v) return;
    if (!isValidIP(v) && !isValidDomain(v)) {
      toast.error('Enter a valid IP, CIDR, or domain');
      return;
    }
    addMutation.mutate({ entry: v, description: newDesc.trim() });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-extrabold tracking-tight bg-gradient-to-b from-foreground to-foreground/70 bg-clip-text text-transparent flex items-center">
          <ArrowUpFromLine className="w-6 h-6 mr-2 text-primary" />Egress Allowlist
        </h1>
        <p className="text-muted-foreground">Destinations a client may reach when default-deny egress is on</p>
      </div>

      <Card>
        <CardContent className="p-4 flex items-start gap-3">
          <ShieldCheck className="w-5 h-5 text-primary mt-0.5 shrink-0" />
          <p className="text-sm text-muted-foreground">
            When <span className="font-medium text-foreground">Default-deny egress</span> is enabled in
            {' '}<span className="font-medium text-foreground">Settings</span>, a client behind the proxy may reach
            {' '}<span className="font-medium text-foreground">only</span> the destinations listed here (CIDR/IP or
            domain); everything else is denied. Toggling the mode restarts the proxy. With the mode off, this list has
            no effect.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-4 space-y-3">
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              value={newItem}
              onChange={e => setNewItem(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleAdd(); }}
              placeholder="example.com  or  203.0.113.0/24"
              className="flex-1 px-3 py-2 rounded-md bg-background border border-input text-sm"
            />
            <input
              value={newDesc}
              onChange={e => setNewDesc(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleAdd(); }}
              placeholder="Description (optional)"
              className="flex-1 px-3 py-2 rounded-md bg-background border border-input text-sm"
            />
            <button
              type="button"
              onClick={handleAdd}
              disabled={addMutation.isPending}
              className="flex items-center justify-center px-3 py-2 rounded-md text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              <Plus className="w-4 h-4 mr-1.5" />Add
            </button>
          </div>
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0); }}
            placeholder="Search..."
            className="w-full px-3 py-2 rounded-md bg-background border border-input text-sm"
          />
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="px-4 py-2 font-medium">Destination</th>
                <th className="px-4 py-2 font-medium">Type</th>
                <th className="px-4 py-2 font-medium">Description</th>
                <th className="px-4 py-2 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {entries.length === 0 && (
                <tr><td colSpan={4} className="px-4 py-8 text-center text-muted-foreground">No entries yet</td></tr>
              )}
              {entries.map(row => (
                <tr key={row.id} className="border-b border-border/50 hover:bg-muted/30">
                  <td className="px-4 py-2 font-mono">{row.entry}</td>
                  <td className="px-4 py-2">
                    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                      {row.type === 'cidr' ? <Network className="w-3 h-3" /> : <Globe className="w-3 h-3" />}
                      {row.type}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-muted-foreground">{row.description || '—'}</td>
                  <td className="px-4 py-2 text-right">
                    {pendingDeleteId === row.id ? (
                      <span className="inline-flex gap-1">
                        <button type="button" onClick={() => deleteMutation.mutate(row.id)}
                          className="px-2 py-1 text-xs rounded bg-destructive text-destructive-foreground hover:bg-destructive/90">Confirm</button>
                        <button type="button" onClick={() => setPendingDeleteId(null)}
                          className="px-2 py-1 text-xs rounded bg-secondary hover:bg-secondary/80">Cancel</button>
                      </span>
                    ) : (
                      <button type="button" onClick={() => setPendingDeleteId(row.id)}
                        className="p-1.5 rounded text-destructive hover:bg-destructive/10" title="Remove">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">{total} entries</span>
          <div className="flex gap-2">
            <button type="button" disabled={page === 0} onClick={() => setPage(p => Math.max(0, p - 1))}
              className="px-3 py-1.5 rounded-md bg-secondary hover:bg-secondary/80 disabled:opacity-50">Previous</button>
            <span className="px-2 py-1.5 text-muted-foreground">{page + 1} / {totalPages}</span>
            <button type="button" disabled={page + 1 >= totalPages} onClick={() => setPage(p => p + 1)}
              className="px-3 py-1.5 rounded-md bg-secondary hover:bg-secondary/80 disabled:opacity-50">Next</button>
          </div>
        </div>
      )}
    </div>
  );
}
