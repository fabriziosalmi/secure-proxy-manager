import { useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Menu, X } from 'lucide-react';

export function Layout({ onLogout }: { onLogout?: () => void }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  const handleNav = () => setMobileOpen(false);

  return (
    <div className="flex h-screen bg-background text-foreground overflow-hidden">
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div className={`
        fixed inset-y-0 left-0 z-50 lg:static lg:z-auto
        transform transition-transform duration-200 ease-in-out
        ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        <Sidebar onNavigate={handleNav} onLogout={onLogout} />
      </div>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto custom-scrollbar">
        {/* Mobile top bar */}
        <div className="lg:hidden sticky top-0 z-30 bg-background/80 backdrop-blur-xl border-b border-white/[0.06] px-4 py-3 flex items-center gap-3">
          <button
            type="button"
            onClick={() => setMobileOpen(!mobileOpen)}
            className="p-1.5 rounded-md hover:bg-secondary btn-press"
          >
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
          <div className="w-6 h-6 rounded-md bg-primary/10 flex items-center justify-center">
            <img src="/logo.svg" alt="" className="w-4 h-4" />
          </div>
          <span className="font-semibold text-sm">Proxy Manager</span>
        </div>

        {/* Page content with entrance animation */}
        <div key={location.pathname} className="p-4 lg:p-8 page-enter">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
