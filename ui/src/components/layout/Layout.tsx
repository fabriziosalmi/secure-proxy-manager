/**
 * Layout: the app shell around every page.
 *
 * Wide screens (lg and up): the sidebar sits beside the page and can be
 * collapsed to icons; the choice is kept in localStorage and the app works
 * when storage throws. Small screens: the sidebar is an off-canvas drawer
 * opened by the 44px menu button in the top bar. The open drawer is a modal
 * dialog: focus moves into it, Tab stays inside, Escape, the backdrop, the
 * close button or any route change close it, and focus returns to the menu
 * button. The closed drawer is inert, so its links are not in the tab order.
 *
 * The page is keyed by path, so each route mounts fresh with its entrance
 * animation; error boundaries sit around each route in App.
 */
import { useCallback, useState } from 'react';
import { Outlet, useLocation } from 'react-router';
import { Menu, Search, X } from 'lucide-react';
import { Sidebar, SIDEBAR_ID } from './Sidebar';
import { pageLabel, readCollapsed, writeCollapsed } from './nav';
import { useMediaQuery, DESKTOP_QUERY } from '../../hooks/useMediaQuery';
import { useModal } from '../../hooks/useModal';
import { cn } from '../../lib/utils';

export function Layout({ onLogout }: { onLogout?: () => void }) {
  const location = useLocation();
  const isDesktop = useMediaQuery(DESKTOP_QUERY);
  const [collapsedPref, setCollapsedPref] = useState(readCollapsed);
  // The drawer is open only on the path it was opened on: any navigation
  // closes it without an effect, whatever triggered the navigation.
  const [openedAt, setOpenedAt] = useState<string | null>(null);

  const drawerOpen = !isDesktop && openedAt === location.pathname;
  const collapsed = isDesktop && collapsedPref;

  const closeDrawer = useCallback(() => setOpenedAt(null), []);
  const drawerRef = useModal<HTMLDivElement>(drawerOpen, closeDrawer);

  const toggleCollapsed = () => {
    const next = !collapsedPref;
    setCollapsedPref(next);
    writeCollapsed(next);
  };

  const title = pageLabel(location.pathname);

  return (
    <div className="flex h-screen overflow-hidden bg-ground text-ink">
      {drawerOpen && (
        <div aria-hidden="true" data-testid="drawer-backdrop" className="fixed inset-0 z-40 bg-[rgba(16,24,40,0.45)]" onClick={closeDrawer} />
      )}

      <div
        id={SIDEBAR_ID}
        ref={drawerRef}
        role={drawerOpen ? 'dialog' : undefined}
        aria-modal={drawerOpen ? true : undefined}
        aria-label={drawerOpen ? 'Navigation' : undefined}
        inert={!isDesktop && !drawerOpen}
        className={cn(
          'fixed inset-y-0 left-0 z-50 transition-transform duration-200 ease-out lg:static lg:z-auto lg:translate-x-0',
          drawerOpen ? 'translate-x-0 shadow-[0_12px_24px_rgba(16,24,40,0.18)]' : '-translate-x-full',
        )}
      >
        <Sidebar
          collapsed={collapsed}
          onToggleCollapsed={isDesktop ? toggleCollapsed : undefined}
          drawer={!isDesktop}
          onClose={closeDrawer}
          onNavigate={closeDrawer}
          onLogout={onLogout}
        />
      </div>

      <main className="min-w-0 flex-1 overflow-y-auto custom-scrollbar">
        {/* Small-screen top bar */}
        <div className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b border-line bg-surface pl-1 pr-2 lg:hidden">
          <button
            type="button"
            onClick={() => setOpenedAt(drawerOpen ? null : location.pathname)}
            aria-label={drawerOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={drawerOpen}
            aria-controls={SIDEBAR_ID}
            className="flex h-11 w-11 items-center justify-center rounded-control text-ink-secondary hover:bg-surface-muted focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
          >
            {drawerOpen ? <X aria-hidden="true" className="h-[22px] w-[22px]" /> : <Menu aria-hidden="true" className="h-[22px] w-[22px]" strokeWidth={1.75} />}
          </button>
          <span className="flex-1 truncate text-[17px] font-semibold text-ink">{title ?? 'Secure Proxy Manager'}</span>
          <button
            type="button"
            aria-label="Search"
            onClick={() => window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true }))}
            className="flex h-11 w-11 items-center justify-center rounded-control text-ink-secondary hover:bg-surface-muted focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
          >
            <Search aria-hidden="true" className="h-5 w-5" strokeWidth={1.75} />
          </button>
        </div>

        {/* Page content, keyed by path for the entrance animation */}
        <div key={location.pathname} className="page-enter mx-auto w-full max-w-[1320px] px-4 py-4 lg:px-10 lg:pb-12 lg:pt-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
