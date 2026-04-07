import { useState, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { LayoutDashboard, Ban, ShieldAlert, List, Settings, Search, Command, LogOut } from 'lucide-react';
import { api } from '../../lib/api';

type ApiStatus = 'connected' | 'disconnected' | 'checking';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/blacklists', icon: Ban, label: 'Blacklists' },
  { to: '/threats', icon: ShieldAlert, label: 'Threat Intel' },
  { to: '/logs', icon: List, label: 'Access Logs' },
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export function Sidebar({ onNavigate, onLogout }: { onNavigate?: () => void; onLogout?: () => void }) {
  const [apiStatus, setApiStatus] = useState<ApiStatus>('checking');
  const [backendInfo, setBackendInfo] = useState<{ version?: string; runtime?: string; update_available?: string; update_url?: string }>({});
  const location = useLocation();

  useEffect(() => {
    const check = async () => {
      try {
        const res = await api.get('/health');
        setApiStatus('connected');
        setBackendInfo({
          version: res.data?.version,
          runtime: res.data?.runtime,
          update_available: res.data?.update_available,
          update_url: res.data?.update_url,
        });
      } catch {
        setApiStatus('disconnected');
      }
    };
    check();
    const interval = setInterval(check, 15000);
    return () => clearInterval(interval);
  }, []);

  // Compute pill position for the active indicator
  const activeIndex = navItems.findIndex(item =>
    item.to === '/' ? location.pathname === '/' : location.pathname.startsWith(item.to)
  );

  return (
    <aside className="w-64 border-r border-white/[0.06] bg-[#060608] flex flex-col h-screen">
      {/* Logo */}
      <div className="h-16 flex items-center px-6 border-b border-white/[0.06]">
        <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center mr-3">
          <img src="/logo.svg" alt="Secure Proxy Manager" className="w-5 h-5" />
        </div>
        <span className="font-bold text-base tracking-tight text-white">Proxy Manager</span>
      </div>

      <div className="p-4">
        {/* Search trigger */}
        <button
          type="button"
          onClick={() => window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true }))}
          className="w-full flex items-center gap-2 px-3 py-2 mb-4 glass-surface rounded-lg text-xs text-muted-foreground hover:text-foreground transition-all btn-press"
        >
          <Search className="w-3.5 h-3.5 shrink-0" />
          <span className="flex-1 text-left">Search...</span>
          <kbd className="flex items-center gap-0.5 px-1.5 py-0.5 bg-white/[0.06] rounded text-[10px] font-mono">
            <Command className="w-2.5 h-2.5" />K
          </kbd>
        </button>

        <div className="text-[10px] font-medium text-muted-foreground/60 mb-3 uppercase tracking-[0.15em]">
          Navigation
        </div>

        {/* Nav with animated pill indicator */}
        <nav className="relative space-y-0.5">
          {/* Sliding active indicator */}
          {activeIndex >= 0 && (
            <div
              className="absolute left-0 w-[3px] h-8 bg-primary rounded-full transition-all duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]"
              style={{ top: `${activeIndex * 36 + 4}px` }}
            />
          )}

          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={onNavigate}
              className={({ isActive }) =>
                `flex items-center px-3 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                  isActive
                    ? 'bg-white/[0.06] text-white'
                    : 'text-muted-foreground hover:bg-white/[0.04] hover:text-white'
                }`
              }
            >
              <item.icon className="w-4 h-4 mr-3" />
              {item.label}
            </NavLink>
          ))}
        </nav>
      </div>

      <div className="mt-auto p-3 border-t border-white/[0.06] space-y-2">
        {/* System status panel */}
        <div className="rounded-lg glass-surface p-3 space-y-3">
          {/* Connection row */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="relative flex items-center justify-center w-5 h-5">
                {/* Outer ring */}
                <div className={`absolute inset-0 rounded-full border ${
                  apiStatus === 'connected' ? 'border-emerald-500/30' :
                  apiStatus === 'disconnected' ? 'border-red-500/30' : 'border-yellow-500/30'
                }`} />
                {/* Inner dot */}
                <div className={`w-2 h-2 rounded-full ${
                  apiStatus === 'connected' ? 'bg-emerald-500' :
                  apiStatus === 'disconnected' ? 'bg-red-500' : 'bg-yellow-500'
                }`} />
                {/* Ping animation */}
                {apiStatus === 'connected' && (
                  <div className="absolute inset-0 rounded-full border border-emerald-500/40 animate-status-ping" />
                )}
                {apiStatus === 'checking' && (
                  <div className="absolute inset-0 rounded-full border border-yellow-500/40 animate-pulse" />
                )}
              </div>
              <div>
                <p className="text-[11px] font-semibold leading-none text-foreground">
                  {apiStatus === 'connected' ? 'System Online' : apiStatus === 'disconnected' ? 'Disconnected' : 'Connecting...'}
                </p>
                <p className="text-[9px] text-muted-foreground/60 mt-0.5">API backend</p>
              </div>
            </div>
            <div className={`px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase tracking-wider ${
              apiStatus === 'connected' ? 'bg-emerald-500/10 text-emerald-400' :
              apiStatus === 'disconnected' ? 'bg-red-500/10 text-red-400' : 'bg-yellow-500/10 text-yellow-400'
            }`}>
              {apiStatus === 'connected' ? 'OK' : apiStatus === 'disconnected' ? 'ERR' : '...'}
            </div>
          </div>

          {/* Divider */}
          <div className="border-t border-white/[0.04]" />

          {/* Version + Runtime row */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] text-muted-foreground/50 font-mono leading-none">
                {backendInfo.version || '—'}
              </span>
              {backendInfo.runtime && (
                <span className={`text-[9px] font-mono font-semibold px-1 py-px rounded leading-none ${
                  backendInfo.runtime === 'go' ? 'bg-cyan-500/10 text-cyan-400' : 'bg-yellow-500/10 text-yellow-400'
                }`}>
                  {backendInfo.runtime}
                </span>
              )}
            </div>
            {backendInfo.update_available ? (
              <a
                href={backendInfo.update_url || '#'}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-colors font-mono font-semibold"
              >
                <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 10l7-7m0 0l7 7m-7-7v18"/></svg>
                {backendInfo.update_available}
              </a>
            ) : (
              <span className="text-[9px] text-muted-foreground/30 font-mono">latest</span>
            )}
          </div>
        </div>

        {/* Sign out */}
        {onLogout && (
          <button
            type="button"
            onClick={onLogout}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-[11px] font-medium text-muted-foreground/60 hover:text-destructive hover:bg-destructive/8 transition-all btn-press"
          >
            <LogOut className="w-3 h-3" />
            Sign out
          </button>
        )}
      </div>
    </aside>
  );
}
