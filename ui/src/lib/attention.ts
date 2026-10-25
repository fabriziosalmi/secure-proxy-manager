/**
 * The Overview's "Needs attention" list, worked out from what the API
 * reports: the stored settings, the secrets' state, the proxy status and the
 * size of the egress allowlist. An input that is not known yet produces no
 * item, and one that could not be read says so; nothing here is a guess.
 */
import type { SecretState } from './secrets';
import type { SectionId } from './settingsMeta';
import { EGRESS_EMPTY_REACH } from './egress';

export interface AttentionItem {
  id: string;
  /** warning: something is wrong or will surprise; info: a choice worth knowing. */
  tone: 'warning' | 'info';
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

export function needsAttention({ values, secrets, proxyStatus, egressTotal }: AttentionInput): AttentionItem[] {
  const on = (k: string) => values[k] === 'true';
  const items: AttentionItem[] = [];

  if (proxyStatus === null) {
    items.push({ id: 'proxy-unknown', tone: 'warning', title: 'The proxy status could not be read', body: 'GET /api/status did not answer, so this page cannot tell whether clients can browse.' });
  } else if (proxyStatus !== undefined && proxyStatus !== 'running') {
    items.push({ id: 'proxy-down', tone: 'warning', title: 'The proxy is not running', body: `The backend reports the proxy as "${proxyStatus}". Clients cannot browse until the proxy container runs.` });
  }

  if (on('egress_default_deny')) {
    if (egressTotal === 0) {
      items.push({ id: 'egress-empty', tone: 'warning', title: 'Clients reach only LAN destinations and Allowed IPs', body: `Only allowlisted destinations is on and the egress allowlist is empty. ${EGRESS_EMPTY_REACH}`, section: 'filtering', action: 'Filtering' });
    } else if (egressTotal === null) {
      items.push({ id: 'egress-unknown', tone: 'warning', title: 'The egress allowlist could not be read', body: 'Only allowlisted destinations is on, and this page cannot tell how many destinations are allowed.', section: 'filtering', action: 'Filtering' });
    }
  }

  if (on('enable_content_filtering') && !(values.blocked_file_types ?? '').split(',').some((s) => s.trim())) {
    items.push({ id: 'downloads-empty', tone: 'warning', title: 'Risky downloads are not blocked', body: 'Block risky downloads is on but lists no extension, so the proxy blocks nothing.', section: 'filtering', action: 'Filtering' });
  }

  const unreadable = Object.entries(secrets).filter(([, s]) => s === 'unreadable').map(([k]) => k);
  if (unreadable.length) {
    items.push({
      id: 'secrets-unreadable',
      tone: 'warning',
      title: unreadable.length === 1 ? 'An alert setting cannot be read' : `${unreadable.length} alert settings cannot be read`,
      body: 'They were stored with another encryption key. Enter them again.',
      section: 'alerts',
      action: 'Alerts',
    });
  }

  const channels = configuredChannels(secrets);
  if (on('enable_notifications') && channels.length === 0) {
    items.push({ id: 'alerts-no-channel', tone: 'warning', title: 'Alerts are on but go nowhere', body: 'No alert channel has all of its settings stored.', section: 'alerts', action: 'Set up alerts' });
  }

  if (values.default_password_changed !== undefined && values.default_password_changed !== 'true') {
    items.push({ id: 'password', tone: 'warning', title: 'The admin password was never changed here', body: 'It is still the one the install started with.', section: 'admin', action: 'Admin and backup' });
  }

  if (values.proxy_port !== undefined && values.proxy_port !== '3128') {
    items.push({
      id: 'port',
      tone: 'warning',
      title: `The proxy is set to listen on ${values.proxy_port}`,
      body: 'docker-compose.yml publishes 3128 and its health check looks for 3128, so clients cannot reach the proxy unless the compose file was changed to match.',
      section: 'engine',
      action: 'Proxy engine',
    });
  }

  if (on('ssl_bump_enabled')) {
    items.push({ id: 'https-on', tone: 'info', title: 'HTTPS inspection is on', body: 'A device without the proxy CA installed sees a certificate error on every HTTPS site.', section: 'inspection', action: 'Inspection' });
  } else if (values.ssl_bump_enabled !== undefined) {
    items.push({ id: 'https-off', tone: 'info', title: 'HTTPS traffic is not inspected', body: 'HTTPS requests pass as encrypted tunnels: the WAF and the download filter see only the destination name.', section: 'inspection', action: 'Inspection' });
  }

  if (!on('enable_notifications') && values.enable_notifications !== undefined) {
    items.push({ id: 'alerts-off', tone: 'info', title: 'Blocks are not reported anywhere', body: 'Alerts are off, so a block shows only in the logs.', section: 'alerts', action: 'Set up alerts' });
  }

  if (!on('enable_proxy_auth')) {
    items.push({ id: 'no-login', tone: 'info', title: 'Any device on a private network can use the proxy without signing in', body: 'Fine on a home network. Turn on proxy login if guests share it.', section: 'access', action: 'Clients and access' });
  }

  return items;
}
