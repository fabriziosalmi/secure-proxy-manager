import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, ArrowRight, Ban, Shield, List, Settings, LayoutDashboard, X } from 'lucide-react';
import { api } from '../lib/api';

interface SearchResult {
  type: 'page' | 'ip' | 'domain' | 'log' | 'setting';
  label: string;
  description?: string;
  action: () => void;
}

const PAGES: { path: string; label: string; icon: typeof LayoutDashboard; keywords: string[] }[] = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard, keywords: ['home', 'overview', 'stats', 'traffic'] },
  { path: '/blacklists', label: 'Blacklists', icon: Ban, keywords: ['ip', 'domain', 'block', 'whitelist', 'geo'] },
  { path: '/threats', label: 'Threat Intelligence', icon: Shield, keywords: ['waf', 'threat', 'attack', 'security'] },
  { path: '/logs', label: 'Access Logs', icon: List, keywords: ['log', 'traffic', 'request', 'access'] },
  { path: '/settings', label: 'Settings', icon: Settings, keywords: ['config', 'proxy', 'port', 'cache', 'tailscale', 'dns'] },
];

export function GlobalSearch() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [selected, setSelected] = useState(0);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  // Cmd+K / Ctrl+K to open
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen(o => !o);
      }
      if (e.key === 'Escape') setOpen(false);
      // Number keys for navigation (only when search is closed)
      if (!open && !e.metaKey && !e.ctrlKey && !e.altKey) {
        const target = e.target as HTMLElement;
        if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) return;
        const num = parseInt(e.key);
        if (num >= 1 && num <= 5) {
          e.preventDefault();
          navigate(PAGES[num - 1].path);
        }
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, navigate]);

  // Focus input on open
  useEffect(() => {
    if (open) {
      setQuery('');
      setResults([]);
      setSelected(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  // Search logic
  const search = useCallback(async (q: string) => {
    if (!q.trim()) { setResults([]); return; }
    const lower = q.toLowerCase();
    const items: SearchResult[] = [];

    // Page matches
    PAGES.forEach(p => {
      if (p.label.toLowerCase().includes(lower) || p.keywords.some(k => k.includes(lower))) {
        items.push({ type: 'page', label: p.label, description: `Go to ${p.label}`, action: () => { navigate(p.path); setOpen(false); } });
      }
    });

    // API search (IP, domain, logs)
    if (q.length >= 2) {
      setLoading(true);
      try {
        const [ipRes, domRes, logRes] = await Promise.allSettled([
          api.get(`ip-blacklist?search=${encodeURIComponent(q)}&page=1&page_size=5`),
          api.get(`domain-blacklist?search=${encodeURIComponent(q)}&page=1&page_size=5`),
          api.get(`logs?search=${encodeURIComponent(q)}&limit=5`),
        ]);

        if (ipRes.status === 'fulfilled') {
          const ips = ipRes.value.data?.data || [];
          ips.forEach((ip: Record<string, string>) => {
            items.push({
              type: 'ip', label: ip.ip,
              description: ip.description || 'IP blacklist entry',
              action: () => { navigate('/blacklists'); setOpen(false); },
            });
          });
        }

        if (domRes.status === 'fulfilled') {
          const doms = domRes.value.data?.data || [];
          doms.forEach((d: Record<string, string>) => {
            items.push({
              type: 'domain', label: d.domain,
              description: d.description || 'Domain blacklist entry',
              action: () => { navigate('/blacklists'); setOpen(false); },
            });
          });
        }

        if (logRes.status === 'fulfilled') {
          const logs = logRes.value.data?.data || logRes.value.data?.logs || [];
          logs.forEach((l: Record<string, string>) => {
            items.push({
              type: 'log', label: `${l.method || '-'} ${l.destination}`,
              description: `${l.client_ip} — ${l.status}`,
              action: () => { navigate('/logs'); setOpen(false); },
            });
          });
        }
      } catch { /* silently ignore */ }
      setLoading(false);
    }

    setResults(items);
    setSelected(0);
  }, [navigate]);

  // Debounced search
  useEffect(() => {
    const t = setTimeout(() => search(query), 200);
    return () => clearTimeout(t);
  }, [query, search]);

  // Keyboard navigation
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, results.length - 1)); }
    if (e.key === 'ArrowUp') { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)); }
    if (e.key === 'Enter' && results[selected]) { results[selected].action(); }
  };

  if (!open) {
    return null; // Trigger button moved to Sidebar — modal opens via ⌘K or sidebar click
  }

  const typeIcon = (t: string) => {
    switch (t) {
      case 'page': return <ArrowRight className="w-3 h-3 text-primary" />;
      case 'ip': return <Ban className="w-3 h-3 text-destructive" />;
      case 'domain': return <Shield className="w-3 h-3 text-orange-500" />;
      case 'log': return <List className="w-3 h-3 text-blue-500" />;
      case 'setting': return <Settings className="w-3 h-3 text-emerald-500" />;
      default: return <Search className="w-3 h-3" />;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]" onClick={() => setOpen(false)}>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" />
      <div
        className="relative w-full max-w-lg bg-[#0f1117] border border-border/60 rounded-xl shadow-2xl overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Search input */}
        <div className="flex items-center px-4 py-3 border-b border-border/40">
          <Search className="w-4 h-4 text-muted-foreground mr-3 shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Search IPs, domains, logs, pages..."
            className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground outline-none"
          />
          {loading && <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin mr-2" />}
          <button type="button" onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground ml-2">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results */}
        <div className="max-h-[50vh] overflow-y-auto">
          {results.length > 0 ? (
            <div className="py-1">
              {results.map((r, i) => (
                <button
                  key={`${r.type}-${r.label}-${i}`}
                  type="button"
                  onClick={r.action}
                  onMouseEnter={() => setSelected(i)}
                  className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                    i === selected ? 'bg-primary/10' : 'hover:bg-card/50'
                  }`}
                >
                  {typeIcon(r.type)}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{r.label}</p>
                    {r.description && <p className="text-[10px] text-muted-foreground truncate">{r.description}</p>}
                  </div>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-secondary text-muted-foreground uppercase shrink-0">{r.type}</span>
                </button>
              ))}
            </div>
          ) : query.length > 0 && !loading ? (
            <div className="py-8 text-center text-sm text-muted-foreground">No results for "{query}"</div>
          ) : (
            <div className="py-4 px-4">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Quick Navigation</p>
              {PAGES.map((p, i) => (
                <button
                  key={p.path}
                  type="button"
                  onClick={() => { navigate(p.path); setOpen(false); }}
                  className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-left hover:bg-card/50 transition-colors"
                >
                  <p.icon className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="text-sm">{p.label}</span>
                  <kbd className="ml-auto text-[10px] px-1.5 py-0.5 bg-secondary rounded font-mono text-muted-foreground">{i + 1}</kbd>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Footer hints */}
        <div className="flex items-center justify-between px-4 py-2 border-t border-border/40 text-[10px] text-muted-foreground">
          <div className="flex items-center gap-3">
            <span><kbd className="px-1 py-0.5 bg-secondary rounded font-mono">↑↓</kbd> navigate</span>
            <span><kbd className="px-1 py-0.5 bg-secondary rounded font-mono">↵</kbd> select</span>
            <span><kbd className="px-1 py-0.5 bg-secondary rounded font-mono">esc</kbd> close</span>
          </div>
          <div className="flex items-center gap-2">
            {PAGES.map((_, i) => <span key={i}><kbd className="px-1 py-0.5 bg-secondary rounded font-mono">{i+1}</kbd></span>)}
            <span>quick nav</span>
          </div>
        </div>
      </div>
    </div>
  );
}
