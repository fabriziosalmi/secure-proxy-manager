import { useQuery } from '@tanstack/react-query';
import { statusQuery } from '../lib/queries';
import { proxyEndpoints } from '../lib/utils';

/**
 * The address a device configures for the proxy (lib/utils proxyEndpoints),
 * read with the status the Overview already polls. loopback is true when it
 * is the server itself (the UI opened on localhost and no PROXY_IP set),
 * which no other device can reach.
 */
export function useProxyAddress(): ReturnType<typeof proxyEndpoints> {
  const status = useQuery(statusQuery);
  return proxyEndpoints(status.data?.proxy_ip);
}
