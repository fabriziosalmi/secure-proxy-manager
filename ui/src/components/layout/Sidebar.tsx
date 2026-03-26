import { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Ban, List, Settings } from 'lucide-react';
import { api } from '../../lib/api';

type ApiStatus = 'connected' | 'disconnected' | 'checking';

export function Sidebar() {
  const [apiStatus, setApiStatus] = useState<ApiStatus>('checking');

  useEffect(() => {
    const check = async () => {
      try {
        await api.get('/health');
        setApiStatus('connected');
      } catch {
        setApiStatus('disconnected');
      }
    };
    check();
    const interval = setInterval(check, 15000);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/blacklists', icon: Ban, label: 'Blacklists' },
    { to: '/logs', icon: List, label: 'Access Logs' },
    { to: '/settings', icon: Settings, label: 'Settings' },
  ];

  return (
    <aside className="w-64 border-r border-border bg-[#0a0a0a] flex flex-col h-screen">
      <div className="h-16 flex items-center px-6 border-b border-border">
        <img src="/logo.svg" alt="Secure Proxy Manager" className="w-7 h-7 mr-3" />
        <span className="font-semibold text-lg tracking-tight text-white">Proxy Manager</span>
      </div>
      
      <div className="p-4">
        <div className="text-xs font-medium text-muted-foreground mb-4 uppercase tracking-wider">
          Navigation
        </div>
        <nav className="space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-[#1f1f1f] text-white'
                    : 'text-muted-foreground hover:bg-[#1f1f1f] hover:text-white'
                }`
              }
            >
              <item.icon className="w-4 h-4 mr-3" />
              {item.label}
            </NavLink>
          ))}
        </nav>
      </div>

      <div className="mt-auto p-4 border-t border-border">
        <div className="flex items-center justify-between px-3 py-2 mb-2 rounded-md bg-[#0f172a] border border-[#1e293b]">
          <div className="flex items-center">
            <div className={`w-2 h-2 rounded-full mr-2 ${
              apiStatus === 'connected' ? 'bg-emerald-500' :
              apiStatus === 'disconnected' ? 'bg-red-500' : 'bg-yellow-500 animate-pulse'
            }`} />
            <span className="text-sm font-medium text-muted-foreground">API</span>
          </div>
          <span className={`text-xs font-medium ${
            apiStatus === 'connected' ? 'text-emerald-500' :
            apiStatus === 'disconnected' ? 'text-red-500' : 'text-yellow-500'
          }`}>
            {apiStatus === 'connected' ? 'Connected' : apiStatus === 'disconnected' ? 'Offline' : 'Checking…'}
          </span>
        </div>
      </div>
    </aside>
  );
}