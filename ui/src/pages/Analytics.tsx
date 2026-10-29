/**
 * Analytics (route /analytics, formerly Threat Intel at /threats): the last 7
 * days of client traffic, in the viewer's time zone, and what protection is
 * switched on now. Every number is a field of one of these responses:
 *
 * - analytics/blocked-by-day?tz=<zone>: blocked requests per calendar day,
 *   by rule;
 * - analytics/coverage: what is switched on and enforced now;
 * - dashboard/summary (waf, waf_status): the WAF's own category counters,
 *   shared with the Overview's query;
 * - analytics/shadow-it, analytics/user-agents, analytics/file-extensions:
 *   services, kinds of service and file types of the last 7 days.
 *
 * "Client traffic" is what the Overview counts: no DNS sinkhole rows and
 * nothing from the stack's own addresses (#422).
 *
 * Not here any more, because the Overview or the Access logs have it: the
 * most blocked destinations, the live feed of blocks and the hourly timeline.
 * The security score is not shown on any page (GET /api/security/score is
 * retired and answers 410): Protection coverage says what the score only
 * summed up. The
 * top-domains word cloud and the regex playground are gone from this page.
 */
import { Link } from 'react-router';
import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getData } from '../lib/api';
import type { BlockedByDay, Coverage, DashboardSummary, FileExtData, ServiceTypeData, ShadowItService } from '../types';
import { PageHeader } from '../components/ui/PageHeader';
import { BlockedPerDay } from '../components/analytics/BlockedPerDay';
import { ProtectionCoverage } from '../components/analytics/ProtectionCoverage';
import { FileTypes, ServiceKinds, ServicesInUse, WafCategories } from '../components/analytics/TrafficSections';
import { viewerTimeZone } from '../components/analytics/days';

const REFETCH = 60_000;

function usePageVisible(): boolean {
  const [visible, setVisible] = useState(document.visibilityState !== 'hidden');
  useEffect(() => {
    const h = () => setVisible(document.visibilityState !== 'hidden');
    document.addEventListener('visibilitychange', h);
    return () => document.removeEventListener('visibilitychange', h);
  }, []);
  return visible;
}

const LINK = 'rounded-sm text-sm font-semibold text-accent hover:underline focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent';

function state<T>(q: { data?: T | null; isPending: boolean; isError: boolean }) {
  return { data: q.data, loading: q.isPending, error: q.isError };
}

export function Analytics() {
  const visible = usePageVisible();
  const refetchInterval = visible ? REFETCH : false;
  const tz = viewerTimeZone();

  const days = useQuery<BlockedByDay | null>({
    queryKey: ['analytics', 'blocked-by-day', tz],
    queryFn: () => getData<BlockedByDay>(`analytics/blocked-by-day?tz=${encodeURIComponent(tz)}`),
    refetchInterval,
  });
  const coverage = useQuery<Coverage | null>({
    queryKey: ['analytics', 'coverage'],
    queryFn: () => getData<Coverage>('analytics/coverage'),
    refetchInterval,
  });
  // The Overview's query: one fetch serves both pages.
  const summary = useQuery<DashboardSummary | null>({
    queryKey: ['dashboard'],
    queryFn: () => getData<DashboardSummary>('dashboard/summary'),
    refetchInterval: visible ? 30_000 : false,
  });
  const services = useQuery<ShadowItService[] | null>({
    queryKey: ['analytics', 'shadow-it'],
    queryFn: () => getData<ShadowItService[]>('analytics/shadow-it'),
    refetchInterval,
  });
  const kinds = useQuery<ServiceTypeData | null>({
    queryKey: ['analytics', 'user-agents'],
    queryFn: () => getData<ServiceTypeData>('analytics/user-agents'),
    refetchInterval,
  });
  const files = useQuery<FileExtData | null>({
    queryKey: ['analytics', 'file-extensions'],
    queryFn: () => getData<FileExtData>('analytics/file-extensions'),
    refetchInterval,
  });

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Insights"
        title="Analytics"
        description="Client traffic of the last 7 days, and what protection is on now. Each section says what it counts. Times are your local time."
        actions={
          <nav aria-label="Related pages" className="flex flex-wrap gap-4">
            <Link to="/" className={LINK}>Last 24 hours: Overview</Link>
            <Link to="/logs" className={LINK}>Every request: Access logs</Link>
          </nav>
        }
      />

      <div className="flex flex-wrap gap-4">
        <BlockedPerDay data={days.data} loading={days.isPending} error={days.isError} />
        <ProtectionCoverage data={coverage.data} loading={coverage.isPending} error={coverage.isError} />
      </div>

      {/* Two by two, or four in a row on the widest screens: an auto-fit grid
          put three on a row at 1440 px and left the fourth alone. */}
      <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-4">
        <WafCategories summary={state(summary)} />
        <ServicesInUse services={state(services)} onRetry={() => { void services.refetch(); }} />
        <ServiceKinds kinds={state(kinds)} />
        <FileTypes files={state(files)} />
      </div>
    </div>
  );
}
