import { useState, useEffect, useRef, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router';
import { Search, ArrowRight, Ban, CheckCircle, Globe, List, Settings, Shield, X } from 'lucide-react';
import { api } from '../lib/api';
import { useModal } from '../hooks/useModal';
import type { IpEntry, DomainEntry, EgressEntry, LogEntry } from '../types';
import { SECTIONS as SETTINGS_SECTIONS, sectionPath } from '../lib/settingsMeta';
import { NAV_GROUPS } from './layout/nav';
import { cn } from '../lib/utils';

interface SearchResult {
  type: 'page' | 'ip' | 'domain' | 'allowed-ip' | 'allowed-domain' | 'egress' | 'log' | 'setting';
  label: string;
  description?: string;
  action: () => void;
}

// What else a page answers to, beyond its name.
const KEYWORDS: Record<string, string[]> = {
  // The page was called Dashboard in the menu: the old name still finds it.
  '/': ['home', 'dashboard', 'stats', 'traffic'],
  '/analytics': ['waf', 'threat', 'attack', 'security', 'intel', 'statistics'],
  '/logs': ['log', 'traffic', 'request', 'access'],
  '/clients': ['device', 'client', 'ip', 'host'],
  '/blacklists': ['ip', 'domain', 'block', 'whitelist', 'allow', 'geo'],
  '/egress': ['egress', 'allowlist', 'outbound', 'destination', 'deny'],
  '/settings': ['config', 'preferences'],
  '/audit': ['audit', 'history', 'change', 'sign-in', 'login'],
};

// The sidebar's pages, in its order: quick navigation and the 1 to N keys
// follow the navigation instead of a list of their own.
const PAGES = NAV_GROUPS.flatMap((g) => g.items).map((it) => ({ ...it, keywords: KEYWORDS[it.to] ?? [] }));

const TYPE_LABEL: Record<SearchResult['type'], string> = {
  page: 'Page',
  setting: 'Setting',
  ip: 'Blocked IP',
  domain: 'Blocked domain',
  'allowed-ip': 'Allowed IP',
  'allowed-domain': 'Allowed domain',
  egress: 'Egress allowlist',
  log: 'Request',
};

function Kbd({ children }: { children: React.ReactNode }) {
  return <kbd className="rounded border border-line bg-surface-muted px-1.5 py-px font-mono text-[11px] text-ink-secondary">{children}</kbd>;
}

export function GlobalSearch() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [selected, setSelected] = useState(0);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  // Focus-trap + restore + Escape for the search dialog. (Cmd+K to OPEN stays a
  // global shortcut below; only the in-dialog Escape moves to the hook.)
  const dialogRef = useModal<HTMLDivElement>(open, () => setOpen(false));

  // Cmd+K / Ctrl+K to open
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen(o => !o);
      }
      // Escape-to-close is handled by useModal (scoped to the open dialog).
      // Number keys for navigation (only when search is closed)
      if (!open && !e.metaKey && !e.ctrlKey && !e.altKey) {
        const target = e.target as HTMLElement;
        if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) return;
        const num = parseInt(e.key);
        if (num >= 1 && num <= PAGES.length) {
          e.preventDefault();
          navigate(PAGES[num - 1].to);
        }
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, navigate]);

  // Focus input on open; reset state asynchronously to avoid cascading renders
  useEffect(() => {
    if (open) {
      setTimeout(() => {
        setQuery('');
        setResults([]);
        setSelected(0);
        // Initial focus is handled by useModal (focuses the first focusable:
        // the search input).
      }, 0);
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
        items.push({ type: 'page', label: p.label, description: `Go to ${p.label}`, action: () => { navigate(p.to); setOpen(false); } });
      }
    });

    // Settings sections, by name or by what they hold
    SETTINGS_SECTIONS.forEach(sec => {
      if (sec.label.toLowerCase().includes(lower) || sec.keywords.some(k => k.includes(lower))) {
        items.push({ type: 'setting', label: `Settings: ${sec.label}`, description: sec.purpose, action: () => { navigate(sectionPath(sec.id)); setOpen(false); } });
      }
    });

    // API search (IP, domain, whitelists, egress allowlist, logs)
    if (q.length >= 2) {
      setLoading(true);
      try {
        const enc = encodeURIComponent(q);
        const [ipRes, domRes, ipAllowRes, domAllowRes, egressRes, logRes] = await Promise.allSettled([
          // The lists page with limit and offset; page and page_size were
          // ignored, so up to 100 entries of each list came back.
          api.get(`ip-blacklist?search=${enc}&limit=5`),
          api.get(`domain-blacklist?search=${enc}&limit=5`),
          api.get(`ip-whitelist?search=${enc}&limit=5`),
          api.get(`domain-whitelist?search=${enc}&limit=5`),
          api.get(`egress-allowlist?search=${enc}&limit=5`),
          // q is the access log's destination search. "search" was never a
          // parameter of /api/logs: it was ignored and the five newest rows
          // came back as matches for whatever was typed.
          api.get(`logs?q=${enc}&limit=5&sort=id&order=desc`),
        ]);

        if (ipRes.status === 'fulfilled') {
          const ips = ipRes.value.data?.data || [];
          ips.forEach((ip: IpEntry) => {
            items.push({
              type: 'ip', label: ip.ip,
              description: ip.description || 'On the blocked IPs',
              action: () => { navigate(`/blacklists?tab=blocked-ips&q=${enc}`); setOpen(false); },
            });
          });
        }

        if (domRes.status === 'fulfilled') {
          const doms = domRes.value.data?.data || [];
          doms.forEach((d: DomainEntry) => {
            items.push({
              type: 'domain', label: d.domain,
              description: d.description || 'On the blocked domains',
              action: () => { navigate(`/blacklists?tab=blocked-domains&q=${enc}`); setOpen(false); },
            });
          });
        }

        if (ipAllowRes.status === 'fulfilled') {
          const ips = ipAllowRes.value.data?.data || [];
          ips.forEach((ip: IpEntry) => {
            items.push({
              type: 'allowed-ip', label: ip.ip,
              description: ip.description || 'On the allowed IPs',
              action: () => { navigate(`/blacklists?tab=allowed-ips&q=${enc}`); setOpen(false); },
            });
          });
        }

        if (domAllowRes.status === 'fulfilled') {
          const doms = domAllowRes.value.data?.data || [];
          doms.forEach((d: DomainEntry) => {
            items.push({
              type: 'allowed-domain', label: d.domain,
              description: d.description || 'On the allowed domains',
              action: () => { navigate(`/blacklists?tab=allowed-domains&q=${enc}`); setOpen(false); },
            });
          });
        }

        if (egressRes.status === 'fulfilled') {
          const egress = egressRes.value.data?.data || [];
          egress.forEach((e: EgressEntry) => {
            items.push({
              type: 'egress', label: e.entry,
              description: e.description || 'On the egress allowlist',
              action: () => { navigate(`/egress?q=${enc}`); setOpen(false); },
            });
          });
        }

        if (logRes.status === 'fulfilled') {
          const logs = logRes.value.data?.data || logRes.value.data?.logs || [];
          logs.forEach((l: LogEntry) => {
            items.push({
              type: 'log', label: `${l.method || '-'} ${l.destination}`,
              description: `${l.source_ip}, ${l.status}`,
              action: () => { navigate(`/logs?q=${enc}`); setOpen(false); },
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

  if (!open) return null;

  const typeIcon = (t: SearchResult['type']) => {
    const cls = 'h-4 w-4 shrink-0 text-ink-subtle';
    switch (t) {
      case 'page': return <ArrowRight className={cls} aria-hidden="true" />;
      case 'ip': return <Ban className={cls} aria-hidden="true" />;
      case 'domain': return <Globe className={cls} aria-hidden="true" />;
      case 'allowed-ip':
      case 'allowed-domain': return <CheckCircle className={cls} aria-hidden="true" />;
      case 'egress': return <Shield className={cls} aria-hidden="true" />;
      case 'log': return <List className={cls} aria-hidden="true" />;
      case 'setting': return <Settings className={cls} aria-hidden="true" />;
    }
  };

  // Portalled to body: a transformed or filtered ancestor would otherwise
  // become the containing block of this fixed overlay.
  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-start justify-center px-4 pt-[12vh]"
      onClick={() => setOpen(false)}
      role="dialog"
      aria-modal="true"
      aria-labelledby="global-search-title"
    >
      <h2 id="global-search-title" className="sr-only">Global search</h2>
      <div className="fixed inset-0 bg-black/50" aria-hidden="true" />
      <div
        ref={dialogRef}
        className="relative w-full max-w-xl overflow-hidden rounded-panel border border-line bg-surface text-ink shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-line-subtle px-4 py-3">
          <Search className="h-4 w-4 shrink-0 text-ink-subtle" aria-hidden="true" />
          <input
            ref={inputRef}
            role="combobox"
            aria-expanded={results.length > 0}
            aria-controls="global-search-listbox"
            aria-autocomplete="list"
            aria-activedescendant={results.length > 0 && results[selected] ? `global-search-option-${selected}` : undefined}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Search IPs, domains, requests, pages"
            aria-label="Search IPs, domains, requests, pages"
            className="h-8 min-w-0 flex-1 bg-transparent text-sm text-ink placeholder:text-ink-subtle outline-hidden"
          />
          {loading && (
            <div role="status" aria-label="Searching" className="h-4 w-4 animate-spin rounded-full border-2 border-accent border-t-transparent" />
          )}
          <button
            type="button"
            onClick={() => setOpen(false)}
            aria-label="Close search"
            className="rounded-control p-1 text-ink-subtle hover:bg-surface-muted hover:text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="sr-only" aria-live="polite" aria-atomic="true">
          {query.trim().length > 0 && !loading
            ? results.length === 0
              ? `No results for "${query}"`
              : `${results.length} ${results.length === 1 ? 'result' : 'results'} available`
            : ''}
        </div>

        <div className="max-h-[55vh] overflow-y-auto">
          {results.length > 0 ? (
            <ul id="global-search-listbox" role="listbox" aria-label="Search results" className="p-2">
              {results.map((r, i) => (
                <li
                  key={`${r.type}-${r.label}-${i}`}
                  id={`global-search-option-${i}`}
                  role="option"
                  aria-selected={i === selected}
                  onClick={r.action}
                  onMouseEnter={() => setSelected(i)}
                  className={cn(
                    'flex w-full cursor-pointer items-center gap-3 rounded-control px-3 py-2 text-left',
                    i === selected ? 'bg-accent-subtle' : 'hover:bg-surface-muted',
                  )}
                >
                  {typeIcon(r.type)}
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-ink">{r.label}</span>
                    {r.description && <span className="block truncate text-xs text-ink-muted">{r.description}</span>}
                  </span>
                  <span className="shrink-0 text-xs text-ink-muted">{TYPE_LABEL[r.type]}</span>
                </li>
              ))}
            </ul>
          ) : query.length > 0 && !loading ? (
            <p className="px-4 py-8 text-center text-sm text-ink-muted">No results for “{query}”</p>
          ) : (
            <div className="p-2">
              <p className="px-3 pb-1 pt-2 text-xs font-medium text-ink-muted">Go to</p>
              <ul>
                {PAGES.map((p, i) => (
                  <li key={p.to}>
                    <button
                      type="button"
                      onClick={() => { navigate(p.to); setOpen(false); }}
                      className="flex w-full items-center gap-3 rounded-control px-3 py-2 text-left text-sm text-ink hover:bg-surface-muted focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      <p.icon className="h-4 w-4 shrink-0 text-ink-subtle" aria-hidden="true" />
                      <span className="flex-1">{p.label}</span>
                      <Kbd>{i + 1}</Kbd>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line-subtle bg-surface-muted px-4 py-2 text-xs text-ink-muted">
          <span className="flex items-center gap-1.5"><Kbd>↑</Kbd><Kbd>↓</Kbd> move</span>
          <span className="flex items-center gap-1.5"><Kbd>↵</Kbd> open</span>
          <span className="flex items-center gap-1.5"><Kbd>esc</Kbd> close</span>
          <span className="ml-auto hidden sm:inline">Outside a field, keys 1 to {PAGES.length} open a page</span>
        </div>
      </div>
    </div>,
    document.body,
  );
}
