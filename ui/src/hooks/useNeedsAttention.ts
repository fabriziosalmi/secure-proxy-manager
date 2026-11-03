/**
 * The "Needs attention" list (lib/attention) with the queries it reads: the
 * stored settings, the status, what the WAF runs and, when default-deny is on
 * or the caller asks, the egress allowlist. Settings and the Overview page
 * read it from here, so the two cannot report the running configuration
 * differently.
 */
import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { needsAttention, type AttentionItem } from '../lib/attention';
import { settingsQuery, statusQuery, useEgressSummary, wafStatusQuery } from '../lib/queries';
import { parseSettings } from '../lib/secrets';

interface Options {
  /** Read the egress allowlist even with default-deny off (Settings, Filtering). */
  egress?: boolean;
  refetchInterval?: number | false;
}

export interface NeedsAttention {
  items: AttentionItem[];
  /** Whether the settings have loaded: until they have, the list is incomplete. */
  settingsLoaded: boolean;
  settingsPending: boolean;
}

export function useNeedsAttention({ egress = false, refetchInterval }: Options = {}): NeedsAttention {
  const settings = useQuery({ ...settingsQuery, refetchInterval });
  const parsed = useMemo(() => parseSettings(settings.data), [settings.data]);
  const status = useQuery({ ...statusQuery, refetchInterval, staleTime: 10_000 });
  const waf = useQuery({ ...wafStatusQuery, refetchInterval, staleTime: 10_000 });
  const egressSummary = useEgressSummary({ enabled: egress || parsed.values.egress_default_deny === 'true' });

  // The stored values, not a draft: it describes what is running.
  const items = useMemo(() => needsAttention({
    values: parsed.values,
    secrets: parsed.secrets,
    proxyStatus: status.isError ? null : status.data ? (status.data.proxy_status ?? 'unknown') : undefined,
    egressTotal: egressSummary.manual,
    egressProviderEntries: egressSummary.providerEntries,
    proxyAuth: status.data?.proxy_auth,
    waf: waf.isError ? null : waf.data,
  }), [parsed, status.isError, status.data, egressSummary.manual, egressSummary.providerEntries, waf.isError, waf.data]);

  return { items, settingsLoaded: settings.isSuccess, settingsPending: settings.isPending };
}
