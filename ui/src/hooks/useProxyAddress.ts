import { useQuery } from '@tanstack/react-query';
import { statusQuery } from '../lib/queries';
import { isLoopbackHost, proxyAddress, proxyHost } from '../lib/utils';

/**
 * The address a device configures for the proxy (lib/utils proxyHost), read
 * with the status the Overview already polls. loopback is true when it is
 * the server itself (the UI opened on localhost and no PROXY_IP set), which
 * no other device can reach.
 */
export function useProxyAddress(): { host: string; address: string; loopback: boolean; pacURL: string } {
  const status = useQuery(statusQuery);
  const ip = status.data?.proxy_ip;
  const host = proxyHost(ip);
  return { host, address: proxyAddress(ip), loopback: isLoopbackHost(host), pacURL: `http://${host}/wpad.dat` }; // slopless-disable-line VBC-034 -- devices fetch the PAC file over plain HTTP on port 80, where nginx serves it (WPAD)
}
