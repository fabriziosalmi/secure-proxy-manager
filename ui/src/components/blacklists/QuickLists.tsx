/**
 * One-click list additions next to the list they change: common services for
 * the domain whitelist (so the DNS blocklist never blocks them) and public
 * DNS-over-HTTPS resolvers for the domain blacklist (so a device cannot step
 * around the DNS blocklist).
 *
 * The groups are the backend's presets (GET {list}/presets). Adding one is
 * one request (POST {list}/presets/{id}): its domains go on the list under a
 * source of their own ("Common services: Docker"), the audit log records one
 * event, and the export it triggers reloads the DNS sinkhole. The page used to
 * hold the groups and add each domain with its own request, as a "Manual"
 * entry with an audit row each.
 */
import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, getData, getErrorMessage } from '../../lib/api';
import { Section } from '../ui/Section';
import { Button } from '../ui/Button';
import { formatCount } from '../../lib/format';

type PresetList = 'domain-whitelist' | 'domain-blacklist';

/** One preset as GET {list}/presets returns it. */
export interface PresetState {
  id: string;
  name: string;
  domains: string[];
  /** The preset's domains already on the list, whatever source added them. */
  listed: string[];
}

function presetsQuery(list: PresetList) {
  return {
    queryKey: ['lists', list, 'presets'],
    queryFn: () => getData<PresetState[]>(`${list}/presets`),
  };
}

function describe(name: string, added: number, already: number): string {
  const parts = [`${formatCount(added)} added`];
  if (already) parts.push(`${formatCount(already)} already listed`);
  return `${name}: ${parts.join(', ')}. The lists are being sent to the proxy and the DNS sinkhole.`;
}

function usePresetAdder(list: PresetList) {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState('');
  const add = async (p: PresetState) => {
    setBusy(p.id);
    try {
      const res = await api.post(`${list}/presets/${encodeURIComponent(p.id)}`);
      const data = res.data?.data as { added?: string[]; already?: number } | undefined;
      setResult(describe(p.name, data?.added?.length ?? 0, data?.already ?? 0));
    } catch (err) {
      setResult(`${p.name}: ${getErrorMessage(err, 'not added, the backend did not answer')}.`);
    } finally {
      setBusy(null);
      void queryClient.invalidateQueries({ queryKey: ['lists'] });
    }
  };
  return { busy, result, add };
}

export function EssentialWhitelist() {
  const presets = useQuery(presetsQuery('domain-whitelist'));
  const { busy, result, add } = usePresetAdder('domain-whitelist');
  return (
    <Section title="Add common services" description="Whitelists the domains these services need, so the DNS blocklist never blocks them, then reloads DNS.">
      {presets.isError ? (
        <p role="alert" className="text-sm text-ink-muted">The presets could not be read: domain-whitelist/presets did not answer.</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {(presets.data ?? []).map((p) => (
            <Button key={p.id} size="sm" disabled={busy !== null} title={p.domains.join(', ')} onClick={() => void add(p)}>
              {busy === p.id ? `Adding ${p.name}...` : `+ ${p.name}`}
            </Button>
          ))}
        </div>
      )}
      {result && <p role="status" className="mt-3 text-sm text-ink-secondary">{result}</p>}
    </Section>
  );
}

export function BlockDoh() {
  const presets = useQuery(presetsQuery('domain-blacklist'));
  const { busy, result, add } = usePresetAdder('domain-blacklist');
  const doh = presets.data?.find((p) => p.id === 'doh');
  const count = doh?.domains.length;
  return (
    <Section
      title="Block DNS-over-HTTPS"
      description={`Blacklists ${count === undefined ? 'the' : formatCount(count)} public DoH resolvers (Google, Cloudflare, Quad9 and others), so devices cannot step around the DNS blocklist with encrypted DNS, then reloads DNS.`}
    >
      {presets.isError ? (
        <p role="alert" className="text-sm text-ink-muted">The presets could not be read: domain-blacklist/presets did not answer.</p>
      ) : (
        <Button size="sm" variant="danger-outline" disabled={busy !== null || !doh} title={doh?.domains.join(', ')} onClick={() => { if (doh) void add(doh); }}>
          {busy ? 'Blocking...' : 'Block DoH resolvers'}
        </Button>
      )}
      {result && <p role="status" className="mt-3 text-sm text-ink-secondary">{result}</p>}
    </Section>
  );
}
