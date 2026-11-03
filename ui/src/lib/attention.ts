/**
 * The "Needs attention" list, worked out from what the API reports: the
 * stored settings, the secrets' state, the proxy status, the size of the
 * egress allowlist and what the WAF runs. Settings, Overview shows every
 * item; the Overview page shows those that need attention. An input that is
 * not known yet produces no item, and one that could not be read says so;
 * nothing here is a guess.
 */
import type { WafCoverage } from '../types';
import type { SecretState } from './secrets';
import type { ProxyAuthStatus } from './queries';
import type { SectionId } from './settingsMeta';
import { EGRESS_EMPTY_REACH } from './egress';
import { SHARED_SEVERITY, type Posture } from './posture';

export interface AttentionItem {
  id: string;
  /**
   * In the one model Analytics shares (lib/posture): needs-attention when
   * something is wrong or will surprise, worth-knowing for a choice with a
   * cost.
   */
  posture: Extract<Posture, 'needs-attention' | 'worth-knowing'>;
  title: string;
  body: string;
  section?: SectionId;
  action?: string;
}

export interface AttentionInput {
  values: Record<string, string>;
  secrets: Record<string, SecretState>;
  /** GET /api/status proxy_status; undefined while loading, null when it failed. */
  proxyStatus: string | undefined | null;
  /** The egress allowlist size; undefined while loading, null when it failed. */
  egressTotal: number | undefined | null;
  /** Entries from enabled egress provider lists; null when reading providers failed. */
  egressProviderEntries?: number | null;
  /** GET /api/status proxy_auth: what the proxy did about proxy login; undefined when not reported. */
  proxyAuth?: ProxyAuthStatus;
  /** GET /api/waf/status; undefined while loading, null when the request failed. */
  waf?: WafCoverage | null;
}

/** The sentence the dashboard uses for login on with nothing to check it against. */
export const PROXY_LOGIN_NO_CREDENTIALS = 'Proxy login is on but no proxy credentials are set: every client is refused until you set them';

/**
 * Whether proxy login is on with no credentials to check: the stored
 * settings lack the username or the password, or the proxy itself reports
 * that it has no user (its password file could not be written, for one).
 */
export function proxyLoginWithoutCredentials(
  values: Record<string, string>,
  secrets: Record<string, SecretState>,
  proxyAuth?: ProxyAuthStatus,
): boolean {
  if (proxyAuth?.state === 'no_credentials') return true;
  if (values.enable_proxy_auth !== 'true') return false;
  return !values.proxy_auth_username || (secrets.proxy_auth_password ?? 'unset') === 'unset';
}

/** The alert channels notify.go sends to, and the keys each one needs. */
const CHANNELS: Record<string, string[]> = {
  Telegram: ['telegram_bot_token', 'telegram_chat_id'],
  Gotify: ['gotify_url', 'gotify_token'],
  ntfy: ['ntfy_url', 'ntfy_topic'],
  'Microsoft Teams': ['teams_webhook_url'],
  Webhook: ['webhook_url'],
};

export function configuredChannels(secrets: Record<string, SecretState>): string[] {
  return Object.entries(CHANNELS).filter(([, keys]) => keys.every((k) => secrets[k] === 'set')).map(([name]) => name);
}

/**
 * What the WAF says about itself. A WAF in Log only, or one that kept an old
 * policy, still shows as on everywhere else, so both are said here.
 */
function wafItems(waf: WafCoverage | null | undefined): AttentionItem[] {
  if (!waf) return [];
  const where = { section: 'inspection' as const, action: 'Inspection' };
  switch (waf.status) {
    case 'auth_failed':
      return [{
        id: 'waf-refuses-backend',
        posture: 'needs-attention',
        title: 'The WAF refuses the backend',
        body: 'It refused the backend credential, so its state and statistics are not shown. Set INTERNAL_ALERT_TOKEN to the same value on the waf and backend services.',
      }];
    case 'unreachable':
      return [{
        id: 'waf-unreachable',
        posture: 'needs-attention',
        title: 'The backend cannot reach the WAF',
        body: 'Its state is not known. If the WAF itself is down, clients get an error on every request it inspects, unless WAF_FAIL_OPEN=1 lets them through uninspected.',
      }];
    case 'error':
      return [{ id: 'waf-error', posture: 'needs-attention', title: 'The WAF answered the backend with an error', body: 'Its state is not known. The WAF log says why.' }];
  }
  const run = waf.running;
  const items: AttentionItem[] = [];
  if (run?.policy_mode === 'observe') {
    items.push({ id: 'waf-log-only', posture: 'needs-attention', title: 'The WAF is in Log only: it blocks nothing', body: 'It records what it would block. Switch the WAF policy back to Block when you are done.', ...where });
  }
  if (run?.policy_reload_failed) {
    items.push({ id: 'waf-policy-not-reloaded', posture: 'needs-attention', title: 'The WAF could not reload its policy', body: 'It still runs the policy it had before. The WAF policy shows why.', ...where });
  }
  return items;
}

export function needsAttention({ values, secrets, proxyStatus, egressTotal, egressProviderEntries, proxyAuth, waf }: AttentionInput): AttentionItem[] {
  const on = (k: string) => values[k] === 'true';
  const items: AttentionItem[] = [];

  // First: it stops every client, so it is the one to read before any other.
  if (proxyLoginWithoutCredentials(values, secrets, proxyAuth)) {
    items.push({
      id: 'proxy-login-no-credentials',
      posture: SHARED_SEVERITY.proxyLoginWithoutCredentials,
      title: PROXY_LOGIN_NO_CREDENTIALS,
      body: 'Devices get 403 on every request. Set the proxy username and password under Clients and access, Login, or turn proxy login off.',
      section: 'access',
      action: 'Clients and access',
    });
  }

  if (proxyStatus === null) {
    items.push({ id: 'proxy-unknown', posture: 'needs-attention', title: 'The proxy status could not be read', body: 'This page cannot tell whether clients can browse. Detail: GET /api/status did not answer.' });
  } else if (proxyStatus !== undefined && proxyStatus !== 'running') {
    items.push({ id: 'proxy-down', posture: 'needs-attention', title: 'The proxy is not running', body: `The backend reports the proxy as "${proxyStatus}". Clients cannot browse until the proxy container runs.` });
  }

  items.push(...wafItems(waf));

  const effectiveEgressTotal =
    egressTotal === null || egressProviderEntries === null
      ? null
      : egressTotal === undefined
        ? undefined
        : egressTotal + (egressProviderEntries ?? 0);

  if (on('egress_default_deny')) {
    if (effectiveEgressTotal === 0) {
      items.push({ id: 'egress-empty', posture: 'needs-attention', title: 'Clients reach only LAN destinations and IP exceptions', body: `Only allowlisted destinations is on and the default-deny allowlist is empty. ${EGRESS_EMPTY_REACH}`, section: 'filtering', action: 'Filtering' });
    } else if (effectiveEgressTotal === null) {
      items.push({ id: 'egress-unknown', posture: 'needs-attention', title: 'The default-deny allowlist could not be read', body: 'Only allowlisted destinations is on, and this page cannot tell how many destinations are allowed.', section: 'filtering', action: 'Filtering' });
    }
  }

  if (on('enable_content_filtering') && !(values.blocked_file_types ?? '').split(',').some((s) => s.trim())) {
    items.push({ id: 'downloads-empty', posture: 'needs-attention', title: 'Risky downloads are not blocked', body: 'Block risky downloads is on but lists no extension, so the proxy blocks nothing.', section: 'filtering', action: 'Filtering' });
  }

  if (secrets.proxy_auth_password === 'unreadable') {
    items.push({
      id: 'proxy-password-unreadable',
      posture: 'needs-attention',
      title: 'The proxy password cannot be read',
      body: 'It was stored with another encryption key. The proxy keeps the password file it has; enter the password again to replace it.',
      section: 'access',
      action: 'Clients and access',
    });
  }

  const unreadable = Object.entries(secrets).filter(([k, s]) => s === 'unreadable' && k !== 'proxy_auth_password').map(([k]) => k);
  if (unreadable.length) {
    items.push({
      id: 'secrets-unreadable',
      posture: 'needs-attention',
      title: unreadable.length === 1 ? 'An alert setting cannot be read' : `${unreadable.length} alert settings cannot be read`,
      body: 'They were stored with another encryption key. Enter them again.',
      section: 'alerts',
      action: 'Alerts',
    });
  }

  const channels = configuredChannels(secrets);
  if (on('enable_notifications') && channels.length === 0) {
    items.push({ id: 'alerts-no-channel', posture: SHARED_SEVERITY.alertsWithoutChannel, title: 'Alerts are on but go nowhere', body: 'No alert channel has all of its settings stored.', section: 'alerts', action: 'Set up alerts' });
  }

  if (values.default_password_changed !== undefined && values.default_password_changed !== 'true') {
    items.push({ id: 'password', posture: 'needs-attention', title: 'The admin password was never changed here', body: 'It is still the one the install started with.', section: 'admin', action: 'Admin and backup' });
  }

  if (values.proxy_port !== undefined && values.proxy_port !== '3128') {
    items.push({
      id: 'port',
      posture: 'needs-attention',
      title: `The proxy is set to listen on ${values.proxy_port}`,
      body: 'docker-compose.yml publishes 3128 and its health check looks for 3128, so clients cannot reach the proxy unless the compose file was changed to match.',
      section: 'engine',
      action: 'Proxy engine',
    });
  }

  if (on('ssl_bump_enabled')) {
    items.push({ id: 'https-on', posture: 'worth-knowing', title: 'HTTPS inspection is on', body: 'A device without the proxy CA installed sees a certificate error on every HTTPS site.', section: 'inspection', action: 'Inspection' });
  } else if (values.ssl_bump_enabled !== undefined) {
    items.push({ id: 'https-off', posture: SHARED_SEVERITY.httpsOff, title: 'HTTPS traffic is not inspected', body: 'HTTPS requests pass as encrypted tunnels: the WAF and the download filter see only the destination name.', section: 'inspection', action: 'Inspection' });
  }

  if (!on('enable_notifications') && values.enable_notifications !== undefined) {
    items.push({ id: 'alerts-off', posture: SHARED_SEVERITY.alertsOff, title: 'Blocks are not reported anywhere', body: 'Alerts are off, so a block shows only in the logs.', section: 'alerts', action: 'Set up alerts' });
  }

  if (!on('enable_proxy_auth')) {
    items.push({ id: 'no-login', posture: SHARED_SEVERITY.proxyLoginOff, title: 'Any device on a private network can use the proxy without signing in', body: 'Fine on a home network. Turn on proxy login if guests share it.', section: 'access', action: 'Clients and access' });
  }

  return items;
}
