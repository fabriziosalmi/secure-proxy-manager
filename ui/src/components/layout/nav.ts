import { LayoutDashboard, ChartColumn, List, Users, Ban, ArrowUpFromLine, Settings, ScrollText } from 'lucide-react';
import type { StatusData } from '../../lib/queries';

export interface NavItem {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

/** The sidebar, in order. Analytics is the former Threat Intel page. */
export const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Insights',
    items: [
      { to: '/', label: 'Overview', icon: LayoutDashboard },
      { to: '/analytics', label: 'Analytics', icon: ChartColumn },
    ],
  },
  {
    label: 'Traffic',
    items: [
      { to: '/logs', label: 'Access logs', icon: List },
      { to: '/clients', label: 'Clients', icon: Users },
    ],
  },
  {
    label: 'Protection',
    items: [
      { to: '/blacklists', label: 'Blacklists', icon: Ban },
      { to: '/egress', label: 'Default-deny allowlist', icon: ArrowUpFromLine },
    ],
  },
  {
    label: 'System',
    items: [
      { to: '/settings', label: 'Settings', icon: Settings },
      { to: '/audit', label: 'Audit log', icon: ScrollText },
    ],
  },
];

/** "settings" for /settings/alerts, "" for /. */
export const firstSegment = (path: string) => path.split('/').filter(Boolean)[0] ?? '';

/**
 * A nav item is active when the first path segment matches, so
 * /settings/alerts keeps Settings highlighted and / matches only itself.
 */
export function isActivePath(pathname: string, to: string): boolean {
  return firstSegment(pathname) === firstSegment(to);
}

/** The label of the page at this path, for the small-screen top bar. */
export function pageLabel(pathname: string): string | undefined {
  for (const g of NAV_GROUPS) for (const i of g.items) if (isActivePath(pathname, i.to)) return i.label;
  return undefined;
}

// Collapsed sidebar preference. Storage can be missing or throw (private
// mode, blocked site data); the sidebar then starts expanded and still works.
const COLLAPSED_KEY = 'spm.sidebar.collapsed';

/** The saved collapse choice; false when storage is missing or throws. */
export function readCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSED_KEY) === '1';
  } catch {
    return false;
  }
}

/** Save the collapse choice; a storage that throws only loses the memory. */
export function writeCollapsed(collapsed: boolean): void {
  try {
    localStorage.setItem(COLLAPSED_KEY, collapsed ? '1' : '0');
  } catch {
    /* private mode or blocked storage: the choice lasts until reload */
  }
}

// Service health line in the sidebar footer.
export type HealthTone ='success' | 'warning' | 'danger' | 'unknown';

export interface HealthSummary {
  tone: HealthTone;
  text: string;
  /** The services that are down, by name, for the tooltip. */
  down: string[];
}

/**
 * One line of service health from GET /api/status. That endpoint answers for
 * two of the stack's five services: the backend (it answered) and the proxy
 * (proxy_status). The line names those two and nothing it was not told about:
 * it used to read "All 2 services healthy", as if the stack had two.
 * Unknown while loading or when the request failed, never "running".
 */
export function summarizeHealth(status: StatusData | null | undefined, state: 'pending' | 'error' | 'success'): HealthSummary {
  if (state === 'pending') return { tone: 'unknown', text: 'Checking the backend and proxy', down: [] };
  if (state === 'error') return { tone: 'unknown', text: 'Backend not reachable', down: ['Backend'] };
  // It answered without a status body: nothing is known about the proxy.
  if (!status) return { tone: 'unknown', text: 'Status unknown', down: [] };
  if (status.proxy_status === 'running') return { tone: 'success', text: 'Backend and proxy running', down: [] };
  return { tone: 'warning', text: 'Proxy not running', down: ['Proxy'] };
}
