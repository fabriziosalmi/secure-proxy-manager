/**
 * Sidebar: the app's navigation, in the four groups of the approved design
 * (Overview, Traffic, Protection, System).
 *
 * Header: product name, the host the UI is served from and the backend
 * version (GET /api/health). Search opens the GlobalSearch dialog through
 * its own shortcut. Footer: one line of service health from GET /api/status,
 * the theme switch, sign out and, on wide screens, the collapse button.
 *
 * collapsed draws icons only (72px): labels are hidden, every link keeps
 * its aria-label and gets a tooltip. drawer is the small-screen variant,
 * always expanded, with a close button instead of the collapse button.
 * The active item is the one whose first path segment matches the URL, so
 * /settings/alerts keeps Settings active; it carries aria-current="page".
 */
import { useId } from 'react';
import { Link, useLocation } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { Search, LogOut, Sun, Moon, SunMoon, PanelLeftClose, PanelLeftOpen, ShieldCheck, X } from 'lucide-react';
import { useTheme, type Theme } from '../ThemeProvider';
import { healthQuery, statusQuery } from '../../lib/queries';
import { cn, safeExternalUrl } from '../../lib/utils';
import { IconButton, Button } from '../ui/Button';
import { SegmentedControl } from '../ui/SegmentedControl';
import { NAV_GROUPS, isActivePath, summarizeHealth, type HealthTone } from './nav';

export const SIDEBAR_ID = 'app-sidebar';

const THEMES: { value: Theme; label: string; icon: typeof Sun }[] = [
  { value: 'light', label: 'Light theme', icon: Sun },
  { value: 'dark', label: 'Dark theme', icon: Moon },
  { value: 'auto', label: 'Theme follows the system', icon: SunMoon },
];

const DOT: Record<HealthTone, string> = {
  success: 'bg-success-strong',
  warning: 'bg-warning-strong',
  danger: 'bg-danger-strong',
  unknown: 'bg-chart-neutral',
};

const HEALTH_TEXT: Record<HealthTone, string> = {
  success: 'text-ink-muted',
  warning: 'text-warning',
  danger: 'text-danger',
  unknown: 'text-ink-muted',
};

const isMac = () => typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

/** Open GlobalSearch the way its keyboard shortcut does. */
function openSearch() {
  window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true }));
}

export interface SidebarProps {
  collapsed?: boolean;
  /** Present on wide screens: shows the collapse button. */
  onToggleCollapsed?: () => void;
  /** The small-screen drawer variant: always expanded, with a close button. */
  drawer?: boolean;
  onClose?: () => void;
  onNavigate?: () => void;
  onLogout?: () => void;
}

export function Sidebar({ collapsed = false, onToggleCollapsed, drawer, onClose, onNavigate, onLogout }: SidebarProps) {
  const { theme, setTheme } = useTheme();
  const location = useLocation();
  const groupId = useId();
  const status = useQuery({ ...statusQuery, refetchInterval: 30_000, staleTime: 10_000 });
  const health = useQuery({ ...healthQuery, refetchInterval: 300_000, staleTime: 60_000 });

  const host = typeof window !== 'undefined' ? window.location.hostname : '';
  const rawVersion = health.data?.version ?? status.data?.version;
  const version = rawVersion ? `v${rawVersion.replace(/^v/, '')}` : 'version unknown';
  const summary = summarizeHealth(status.data, status.isPending ? 'pending' : status.isError ? 'error' : 'success');
  const healthTitle = summary.down.length ? `Down: ${summary.down.join(', ')}` : summary.text;
  const shortcut = isMac() ? '⌘K' : 'Ctrl K';
  const update = status.data?.update_available;
  const updateUrl = safeExternalUrl(status.data?.update_url);
  const nextTheme = THEMES[(THEMES.findIndex((t) => t.value === theme) + 1) % THEMES.length];
  const currentTheme = THEMES.find((t) => t.value === theme) ?? THEMES[2];

  return (
    <div
      className={cn(
        'flex h-full flex-col border-r border-line bg-surface text-ink-secondary transition-[width] duration-150 ease-out',
        collapsed ? 'w-[72px]' : 'w-[248px]',
      )}
    >
      {/* Header */}
      <div
        className={cn('flex h-16 shrink-0 items-center gap-2.5 border-b border-line-subtle', collapsed ? 'justify-center px-0' : 'px-4')}
        title={collapsed ? `Secure Proxy Manager, ${host}, ${version}` : undefined}
      >
        <div aria-hidden="true" className="flex h-8 w-8 flex-none items-center justify-center rounded-control bg-ink text-surface">
          <ShieldCheck className="h-[18px] w-[18px]" strokeWidth={2} />
        </div>
        {collapsed ? (
          <span className="sr-only">Secure Proxy Manager, {host}, {version}</span>
        ) : (
          <div className="flex min-w-0 flex-1 flex-col leading-tight">
            <span className="truncate text-sm font-semibold text-ink">Secure Proxy Manager</span>
            <span className="truncate text-xs text-ink-subtle">
              {host} &middot; <span className="font-mono">{version}</span>
            </span>
          </div>
        )}
        {drawer && onClose && <IconButton aria-label="Close navigation" icon={<X />} onClick={onClose} />}
      </div>

      {/* Search */}
      <div className="px-3 pb-1 pt-3">
        <button
          type="button"
          aria-label="Search"
          aria-keyshortcuts="Meta+K Control+K"
          title={collapsed ? `Search (${shortcut})` : undefined}
          onClick={openSearch}
          className={cn(
            'flex h-9 w-full items-center gap-2 rounded-control border border-line bg-surface-muted text-[13px] text-ink-subtle transition-colors',
            'hover:text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
            collapsed ? 'justify-center px-0' : 'px-2.5',
          )}
        >
          <Search aria-hidden="true" className="h-4 w-4 shrink-0" strokeWidth={1.75} />
          {!collapsed && (
            <>
              <span className="flex-1 text-left">Search</span>
              <kbd className="rounded border border-line bg-surface px-1.5 py-px font-mono text-[11px] text-ink-subtle">{shortcut}</kbd>
            </>
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav aria-label="Main" className="min-h-0 flex-1 overflow-y-auto px-3 py-2">
        {NAV_GROUPS.map((group, gi) => {
          const headingId = `${groupId}-${gi}`;
          return (
            <div key={group.label}>
              {collapsed && gi > 0 && <div aria-hidden="true" className="mx-1 my-2.5 h-px bg-line-subtle" />}
              <p
                id={headingId}
                className={collapsed ? 'sr-only' : cn('mx-2 mb-1 text-[11px] font-semibold uppercase tracking-[0.04em] text-ink-subtle', gi === 0 ? 'mt-2' : 'mt-4')}
              >
                {group.label}
              </p>
              <ul aria-labelledby={headingId} className="flex flex-col gap-0.5">
                {group.items.map((item) => {
                  const active = isActivePath(location.pathname, item.to);
                  return (
                    <li key={item.to}>
                      <Link
                        to={item.to}
                        onClick={onNavigate}
                        aria-label={item.label}
                        aria-current={active ? 'page' : undefined}
                        title={collapsed ? item.label : undefined}
                        className={cn(
                          'flex h-9 items-center gap-3 rounded-control px-2.5 text-sm transition-colors',
                          'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
                          collapsed && 'justify-center',
                          active ? 'bg-accent-subtle font-semibold text-accent' : 'font-medium text-ink-secondary hover:bg-surface-muted hover:text-ink',
                        )}
                      >
                        <item.icon aria-hidden="true" className="h-[18px] w-[18px] shrink-0" strokeWidth={1.75} />
                        {!collapsed && <span className="truncate">{item.label}</span>}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="flex shrink-0 flex-col gap-2 border-t border-line-subtle p-3">
        <p
          role="status"
          title={healthTitle}
          className={cn('flex min-h-7 items-center gap-2 text-xs', collapsed ? 'justify-center' : 'px-2', HEALTH_TEXT[summary.tone])}
        >
          <span aria-hidden="true" data-tone={summary.tone} className={cn('h-2 w-2 flex-none rounded-full', DOT[summary.tone])} />
          <span className={collapsed ? 'sr-only' : 'truncate'}>{summary.text}</span>
        </p>

        {update && !collapsed && (
          updateUrl === '#' ? (
            <p className="px-2 text-xs font-medium text-accent">Update available: {update}</p>
          ) : (
            <a href={updateUrl} target="_blank" rel="noopener noreferrer" className="px-2 text-xs font-medium text-accent hover:underline">
              Update available: {update}
            </a>
          )
        )}

        {collapsed ? (
          <IconButton
            aria-label={`${currentTheme.label}. Switch to ${nextTheme.label.toLowerCase()}`}
            title={currentTheme.label}
            icon={<currentTheme.icon />}
            onClick={() => setTheme(nextTheme.value)}
            className="self-center"
          />
        ) : (
          <div className="flex items-center justify-between gap-2 px-2">
            <span aria-hidden="true" className="text-xs text-ink-muted">Theme</span>
            <SegmentedControl
              label="Theme"
              size="sm"
              value={theme}
              onChange={setTheme}
              options={THEMES.map((t) => ({ value: t.value, icon: <t.icon />, ariaLabel: t.label }))}
            />
          </div>
        )}

        {onLogout && (
          collapsed ? (
            <IconButton aria-label="Sign out" icon={<LogOut />} onClick={onLogout} className="self-center" />
          ) : (
            <Button variant="ghost" icon={<LogOut />} onClick={onLogout} className="w-full justify-start px-2.5 font-medium">
              Sign out
            </Button>
          )
        )}

        {onToggleCollapsed && (
          <button
            type="button"
            onClick={onToggleCollapsed}
            aria-expanded={!collapsed}
            aria-controls={SIDEBAR_ID}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand sidebar' : undefined}
            className={cn(
              'flex h-9 items-center gap-2.5 rounded-control text-[13px] font-medium text-ink-muted transition-colors',
              'hover:bg-surface-muted hover:text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
              collapsed ? 'justify-center' : 'px-2.5',
            )}
          >
            {collapsed
              ? <PanelLeftOpen aria-hidden="true" className="h-[18px] w-[18px]" strokeWidth={1.75} />
              : <PanelLeftClose aria-hidden="true" className="h-[18px] w-[18px]" strokeWidth={1.75} />}
            {!collapsed && <span>Collapse sidebar</span>}
          </button>
        )}
      </div>
    </div>
  );
}
