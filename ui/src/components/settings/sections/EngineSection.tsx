/**
 * Proxy engine: the listener (shown, not changed here), the cache and its
 * statistics, extra HTTPS ports and offline mode.
 *
 * The port is read-only: the stored proxy_port is the port Squid listens on
 * (squid_settings.env, generate_squid_conf.sh), while docker-compose.yml
 * publishes 3128:3128 and its health check looks for :3128, so a change here
 * alone cuts every client off.
 *
 * "Cache static files longer" was measured on Squid 7.7 from this image: a
 * second request for a .png and a .css was TCP_MEM_HIT with the marker
 * present and TCP_REFRESH_UNMODIFIED without it.
 */
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import type { CacheStats } from '../../../types';
import { getData } from '../../../lib/api';
import { cacheCollected, cacheDisk, cacheHitRatio } from '../../../lib/cacheStats';
import { formatKilobytes, formatCount } from '../../../lib/format';
import { Section } from '../../ui/Section';
import { Notice } from '../../ui/Notice';
import { TextField, ToggleRow } from '../fields';
import type { SectionForm } from '../sectionForm';

function Code({ children }: { children: string }) {
  return <code className="rounded bg-surface-muted px-1 py-px font-mono text-[12px] text-ink">{children}</code>;
}

function CacheStatistics({ inspecting }: { inspecting: boolean }) {
  // The same query as the Overview's Services line.
  const cache = useQuery<CacheStats | null>({ queryKey: ['cache'], queryFn: () => getData<CacheStats>('cache/statistics') });
  const c = cache.data;
  let body: ReactNode;
  if (cache.isPending) body = <p>Reading the cache statistics...</p>;
  else if (cache.isError || !c) body = <p>GET /api/cache/statistics did not answer.</p>;
  else if (c.state === 'not_collected') body = <p>The proxy has not written cache statistics yet. It collects them once a minute while Squid runs.</p>;
  else if (c.state === 'unreadable') body = <p>The backend cannot read the proxy's cache statistics file.</p>;
  else {
    const rows: [string, string][] = [
      ['Hit ratio', cacheHitRatio(c) ?? "Not measured yet (Squid's first minute)"],
      ['Disk', cacheDisk(c) ?? 'Not reported'],
      ['Memory', c.memory_used_kb !== null && c.memory_used_kb !== undefined ? `${formatKilobytes(c.memory_used_kb)} in use` : 'Not reported'],
      ['Objects', c.store_entries !== null && c.store_entries !== undefined ? formatCount(c.store_entries) : 'Not reported'],
    ];
    body = (
      <>
        {c.state === 'stale' && (
          <Notice tone="warning" title="These numbers are out of date" className="mb-3">
            {cacheCollected(c) ?? 'No collection time reported'}. The proxy's watchdog or Squid stopped answering.
          </Notice>
        )}
        <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
          {rows.map(([k, v]) => (
            <div key={k} className="flex flex-col">
              <dt className="text-xs font-semibold uppercase tracking-[0.04em] text-ink-subtle">{k}</dt>
              <dd className="text-sm text-ink">{v}</dd>
            </div>
          ))}
        </dl>
        {c.state === 'current' && <p className="mt-2 text-xs text-ink-muted">{cacheCollected(c)}.</p>}
      </>
    );
  }
  return (
    <div className="flex flex-col gap-3 text-sm text-ink-secondary">
      {body}
      <p className="leading-6">
        HTTPS that is tunnelled without inspection cannot be cached: the proxy passes an encrypted stream it cannot read.
        {inspecting
          ? ' HTTPS inspection is on, so HTTPS responses can be cached too.'
          : ' HTTPS inspection is off, and most sites are HTTPS, so a hit ratio near 0% is expected.'}
      </p>
    </div>
  );
}

export function EngineSection({ form }: { form: SectionForm }) {
  const v = form.values;
  const port = form.stored.proxy_port;
  const offlineOn = v.enable_offline_mode === 'true' && form.stored.enable_offline_mode !== 'true';
  return (
    <div className="flex flex-col gap-4">
      <Section level={3} title="Listener">
        <dl className="flex flex-col">
          <dt className="text-sm font-medium text-ink">Proxy port</dt>
          <dd className="font-mono text-sm text-ink" data-testid="proxy-port">{port ?? 'No port is stored'}</dd>
        </dl>
        <p className="mt-3 text-sm leading-6 text-ink-secondary">
          This page does not change it. Squid listens on the stored port, but <Code>docker-compose.yml</Code> publishes{' '}
          <Code>3128:3128</Code> and its health check looks for <Code>:3128</Code>, and the backend probes <Code>PROXY_PORT</Code> from{' '}
          <Code>.env</Code>. To move it, change all of them together (the stored value with PUT /api/settings/proxy_port), then run{' '}
          <Code>docker compose up -d</Code>. HTTPS inspection only works on 3128.
        </p>
      </Section>

      <Section level={3} title="Cache">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField form={form} setting="cache_size" label="Disk cache (MB)" inputMode="numeric" hint="Space Squid may use in the squid-cache volume. From 1 to 9999999." />
          <TextField form={form} setting="memory_cache" label="Memory cache (MB)" inputMode="numeric" hint="From 1 to 999999. The shipped compose limits the proxy container to 512 MB in all, so keep this well below it." />
        </div>
        <div className="mt-4 flex flex-col gap-4">
          <ToggleRow
            form={form}
            setting="aggressive_caching_enabled"
            label="Cache static files longer"
            help="Keeps images, fonts, stylesheets and scripts fresh for at least 7 days, packages for 1 day and audio and video for 7 days, whatever the site says about expiry, so a repeat request is answered from the cache without asking the site."
          />
          <TextField
            form={form}
            setting="cache_bypass_domains"
            label="Never cache these domains"
            placeholder="e.g. bank.example.com, intranet.example"
            hint="Separated by commas. Each one covers its subdomains."
          />
        </div>
      </Section>

      <Section level={3} title="Cache statistics" description="From the proxy's last collection, once a minute.">
        <CacheStatistics inspecting={form.stored.ssl_bump_enabled === 'true'} />
      </Section>

      <Section level={3} title="Ports and offline mode">
        <TextField
          form={form}
          setting="extra_ssl_ports"
          label="Extra HTTPS ports"
          placeholder="e.g. 8006 8443"
          hint="Ports clients may open HTTPS tunnels to besides 443, separated by commas or spaces, such as 8006 for Proxmox. Applied when the proxy reloads, which saving does."
        />
        <div className="mt-4">
          <ToggleRow
            form={form}
            setting="enable_offline_mode"
            label="Offline mode"
            help="Squid stops checking cached objects with the sites they came from and serves them as they are, stale ones included."
          />
          {offlineOn && (
            <Notice tone="warning" title="Clients may get outdated and other users' pages" className="mt-3">
              Offline mode also writes a refresh rule with ignore-private and ignore-no-store, which lets Squid keep responses a site marks as
              private to one user or not to be stored. Turn it on only for a proxy that serves one person, or while the internet link is down.
            </Notice>
          )}
        </div>
      </Section>
    </div>
  );
}
