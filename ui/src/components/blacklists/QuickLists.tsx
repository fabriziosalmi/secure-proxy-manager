/**
 * One-click list additions that used to sit in Settings, now next to the
 * list they change: common services for the domain whitelist (so the DNS
 * blocklist never blocks them) and public DNS-over-HTTPS resolvers for the
 * domain blacklist (so a device cannot step around the DNS blocklist).
 * Each adds its domains one by one through the list API, asks DNS to
 * reload, and says how many were added, already listed or refused.
 */
import { useState } from 'react';
import axios from 'axios';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../../lib/api';
import { Section } from '../ui/Section';
import { Button } from '../ui/Button';
import { formatCount } from '../../lib/format';

const ESSENTIAL_GROUPS: { label: string; domains: string[] }[] = [
  { label: 'GitHub', domains: ['github.com', 'raw.githubusercontent.com', 'api.github.com', 'gist.github.com', 'objects.githubusercontent.com'] },
  { label: 'Google', domains: ['google.com', 'www.google.com', 'accounts.google.com', 'apis.google.com', 'fonts.googleapis.com', 'fonts.gstatic.com'] },
  { label: 'Microsoft', domains: ['microsoft.com', 'login.microsoftonline.com', 'graph.microsoft.com', 'outlook.office.com'] },
  { label: 'AI Services', domains: ['openai.com', 'api.openai.com', 'claude.ai', 'api.anthropic.com', 'gemini.google.com', 'bard.google.com'] },
  { label: 'Docker', domains: ['docker.com', 'hub.docker.com', 'registry.docker.io', 'auth.docker.io', 'production.cloudflare.docker.com'] },
  { label: 'CDN/JS', domains: ['cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com', 'npmjs.org', 'registry.npmjs.org'] },
  // Not 1.1.1.1 (an address, which the domain whitelist refuses) nor
  // one.one.one.one (a DoH resolver, which Block DoH blacklists).
  { label: 'Cloudflare', domains: ['cloudflare.com', 'dash.cloudflare.com'] },
];

const DOH_DOMAINS = [
  'dns.google', 'dns.google.com', 'dns64.dns.google',
  'cloudflare-dns.com', 'mozilla.cloudflare-dns.com', 'one.one.one.one',
  'doh.opendns.com', 'dns.quad9.net', 'doh.cleanbrowsing.org',
  'dns.adguard.com', 'doh.appliedprivacy.net', 'doh.li',
  'dns.nextdns.io', 'dns.controld.com',
];

interface AddCounts { added: number; already: number; refused: number; failed: number }

/** Add each domain to a list; a 400 that says "already" is a duplicate. */
async function addAll(endpoint: string, domains: string[], description: string): Promise<AddCounts> {
  const results = await Promise.allSettled(domains.map((domain) => api.post(endpoint, { domain, description })));
  const counts: AddCounts = { added: 0, already: 0, refused: 0, failed: 0 };
  for (const r of results) {
    if (r.status === 'fulfilled') { counts.added++; continue; }
    const res = axios.isAxiosError(r.reason) ? r.reason.response : undefined;
    const detail = String(res?.data?.detail ?? '');
    if (res?.status === 400 && /already/i.test(detail)) counts.already++;
    else if (res?.status === 400) counts.refused++;
    else counts.failed++;
  }
  return counts;
}

async function reloadDns(): Promise<boolean> {
  try {
    await api.post('maintenance/reload-dns');
    return true;
  } catch {
    return false;
  }
}

function describe(name: string, c: AddCounts, dns: boolean): string {
  const parts = [`${formatCount(c.added)} added`];
  if (c.already) parts.push(`${formatCount(c.already)} already listed`);
  if (c.refused) parts.push(`${formatCount(c.refused)} refused by the list`);
  if (c.failed) parts.push(`${formatCount(c.failed)} failed, check the connection to the backend`);
  return `${name}: ${parts.join(', ')}. ${dns ? 'DNS reloaded.' : 'DNS was not reloaded: use Reload DNS.'}`;
}

export function EssentialWhitelist() {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState('');
  const add = async (group: (typeof ESSENTIAL_GROUPS)[number]) => {
    setBusy(group.label);
    const counts = await addAll('domain-whitelist', group.domains, `Essential: ${group.label}`);
    const dns = await reloadDns();
    setResult(describe(group.label, counts, dns));
    setBusy(null);
    void queryClient.invalidateQueries({ queryKey: ['whitelist', 'domain'] });
  };
  return (
    <Section title="Add common services" description="Whitelists the domains these services need, so the DNS blocklist never blocks them, then reloads DNS.">
      <div className="flex flex-wrap gap-2">
        {ESSENTIAL_GROUPS.map((g) => (
          <Button key={g.label} size="sm" disabled={busy !== null} title={g.domains.join(', ')} onClick={() => void add(g)}>
            {busy === g.label ? `Adding ${g.label}...` : `+ ${g.label}`}
          </Button>
        ))}
      </div>
      {result && <p role="status" className="mt-3 text-sm text-ink-secondary">{result}</p>}
    </Section>
  );
}

export function BlockDoh() {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState('');
  const block = async () => {
    setBusy(true);
    const counts = await addAll('domain-blacklist', DOH_DOMAINS, 'DoH provider (anti-bypass)');
    const dns = await reloadDns();
    setResult(describe('DoH resolvers', counts, dns));
    setBusy(false);
    void queryClient.invalidateQueries({ queryKey: ['blacklist', 'domain'] });
  };
  return (
    <Section
      title="Block DNS-over-HTTPS"
      description={`Blacklists ${DOH_DOMAINS.length} public DoH resolvers (Google, Cloudflare, Quad9 and others), so devices cannot step around the DNS blocklist with encrypted DNS, then reloads DNS.`}
    >
      <Button size="sm" variant="danger-outline" disabled={busy} title={DOH_DOMAINS.join(', ')} onClick={() => void block()}>
        {busy ? 'Blocking...' : 'Block DoH resolvers'}
      </Button>
      {result && <p role="status" className="mt-3 text-sm text-ink-secondary">{result}</p>}
    </Section>
  );
}
