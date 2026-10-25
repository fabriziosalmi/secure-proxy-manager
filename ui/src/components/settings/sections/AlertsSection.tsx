/**
 * Alerts: where block and sign-in alerts go, and proof that they arrive.
 *
 * Every channel setting is write-only (lib/secrets): the page knows whether a
 * value is stored, never the value. The test (POST /api/notifications/test)
 * sends once to every channel whose settings are all stored and shows what
 * each one answered; it uses the saved channels, so it waits for a save.
 * The events come from backend-go: a failed sign-in (alertLoginFailure) and
 * a WAF block, which the WAF posts to /api/internal/alert with
 * INTERNAL_ALERT_TOKEN. Both pass the notification limits
 * (backend-go/internal/handlers/notify_limit.go): grouping per address, a
 * cap per channel, the type switches and the minimum level. The test does
 * not pass them.
 */
import { useState, type ReactNode } from 'react';
import { api, getErrorMessage } from '../../../lib/api';
import { Section } from '../../ui/Section';
import { Notice } from '../../ui/Notice';
import { Button } from '../../ui/Button';
import { Badge } from '../../ui/Badge';
import { ChoiceRow, SecretRow, TextField, ToggleRow } from '../fields';
import { configuredChannels } from '../../../lib/attention';
import type { SectionForm } from '../sectionForm';

function Code({ children }: { children: string }) {
  return <code className="rounded bg-surface-muted px-1 py-px font-mono text-[12px] text-ink">{children}</code>;
}

interface Channel {
  name: string;
  /** The channel name notify.go reports in a test result. */
  id: string;
  fields: { key: string; label: string; placeholder?: string }[];
  note?: ReactNode;
}

const CHANNELS: Channel[] = [
  {
    name: 'Webhook',
    id: 'webhook',
    fields: [
      { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://alerts.example.com/hook' },
      { key: 'webhook_bearer_token', label: 'Bearer token' },
    ],
    note: <>Each alert is posted as JSON. With a token, each post carries <Code>Authorization: Bearer</Code> and the token, so the receiver can refuse posts that do not come from this backend; without one, anybody who learns the URL can post alerts that look like these.</>,
  },
  {
    name: 'Telegram',
    id: 'telegram',
    fields: [
      { key: 'telegram_bot_token', label: 'Bot token', placeholder: '123456:ABC-DEF1234ghIkl' },
      { key: 'telegram_chat_id', label: 'Chat ID', placeholder: '-1001234567890' },
    ],
  },
  {
    name: 'Gotify',
    id: 'gotify',
    fields: [
      { key: 'gotify_url', label: 'Gotify URL', placeholder: 'https://gotify.example.com' },
      { key: 'gotify_token', label: 'App token' },
    ],
  },
  {
    name: 'ntfy',
    id: 'ntfy',
    fields: [
      { key: 'ntfy_url', label: 'ntfy server URL', placeholder: 'https://ntfy.sh' },
      { key: 'ntfy_topic', label: 'ntfy topic', placeholder: 'proxy-alerts' },
    ],
  },
  {
    name: 'Microsoft Teams',
    id: 'teams',
    fields: [{ key: 'teams_webhook_url', label: 'Teams webhook URL' }],
  },
];

/** notify_min_level: the levels notify_limit.go orders. */
const LEVELS = [
  { value: 'info', label: 'All' },
  { value: 'warning', label: 'Warnings and errors' },
  { value: 'error', label: 'Errors only' },
] as const;

interface ChannelResult { channel: string; delivered: boolean; status?: number; error?: string }
interface TestAnswer {
  message?: string;
  warning?: string;
  data?: { notifications_enabled?: boolean; channels?: ChannelResult[] };
}

type TestState = { kind: 'idle' | 'busy' } | { kind: 'done'; answer: TestAnswer } | { kind: 'failed'; message: string };

const channelName = (id: string) => CHANNELS.find((c) => c.id === id)?.name ?? id;

function TestAlert({ unsaved, enabled }: { unsaved: number; enabled: boolean }) {
  const [state, setState] = useState<TestState>({ kind: 'idle' });
  const send = async () => {
    setState({ kind: 'busy' });
    try {
      const res = await api.post('notifications/test', {});
      setState({ kind: 'done', answer: (res.data ?? {}) as TestAnswer });
    } catch (err) {
      setState({ kind: 'failed', message: getErrorMessage(err, 'the backend did not answer') });
    }
  };
  const answer = state.kind === 'done' ? state.answer : null;
  const results = answer?.data?.channels;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={() => void send()} disabled={state.kind === 'busy' || unsaved > 0}>
          {state.kind === 'busy' ? 'Sending...' : 'Send a test alert'}
        </Button>
        <p className="text-sm text-ink-muted">
          {unsaved > 0
            ? 'Save or discard the changes first: the test uses the saved channels.'
            : 'Sends once to every channel whose settings are all saved, whether alerts are on or not, outside the limits.'}
        </p>
      </div>
      <div aria-live="polite" className="flex flex-col gap-2">
        {state.kind === 'failed' && <Notice tone="danger" title="The test did not run">{state.message}.</Notice>}
        {answer && (
          <>
            <p role="status" className="text-sm font-medium text-ink">
              {answer.message ?? (results ? '' : 'The backend did not report each channel.')}
            </p>
            {results && results.length > 0 && (
              <ul aria-label="Test results" className="flex flex-col gap-1.5">
                {results.map((r) => (
                  <li key={r.channel} className="flex flex-wrap items-center gap-2 text-sm">
                    <Badge tone={r.delivered ? 'success' : 'danger'}>{r.delivered ? 'Delivered' : 'Not delivered'}</Badge>
                    <span className="font-semibold text-ink">{channelName(r.channel)}</span>
                    <span className="text-ink-muted">
                      {r.delivered ? `HTTP ${r.status ?? 'status not reported'}` : (r.error ?? 'no reason reported')}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {answer.data?.notifications_enabled === false && enabled === false && results && results.length > 0 && (
              <Notice tone="warning" title="Alerts are off">
                The test reached the channels above, but real alerts are not sent until Send alerts is on and saved.
              </Notice>
            )}
            {answer.warning && <Notice tone="warning" title="WAF block alerts do not arrive">{answer.warning}</Notice>}
          </>
        )}
      </div>
    </div>
  );
}

export function AlertsSection({ form, unsaved }: { form: SectionForm; unsaved: number }) {
  // What is stored, not the draft: a channel is used once its settings are saved.
  const states = Object.fromEntries(CHANNELS.flatMap((c) => c.fields.map((f) => [f.key, form.secretProps(f.key).state])));
  const ready = new Set(configuredChannels(states));

  return (
    <div className="flex flex-col gap-4">
      <Section level={3} title="Alerts">
        <ToggleRow
          form={form}
          setting="enable_notifications"
          label="Send alerts"
          help={<>Sends failed sign-ins to this dashboard and requests the WAF blocks to every channel below, within the limits under Limits. Block alerts also need <Code>INTERNAL_ALERT_TOKEN</Code> set to the same value on the waf and backend services.</>}
        />
        <ToggleRow
          form={form}
          setting="notify_waf_block"
          label="WAF blocks"
          help="An alert when the WAF blocks a request. Its level is error."
        />
        <ToggleRow
          form={form}
          setting="notify_login_failure"
          label="Failed sign-ins"
          help="An alert when a sign-in to this dashboard fails. Its level is warning."
        />
        <ChoiceRow
          form={form}
          setting="notify_min_level"
          label="Minimum level"
          help="Alerts below this level are not sent."
          options={LEVELS}
        />
      </Section>

      <Section
        level={3}
        title="Limits"
        description="So that a scanner the WAF blocks a thousand times sends a few messages, not a thousand."
      >
        <div className="grid gap-4 md:grid-cols-2">
          <TextField
            form={form}
            setting="notify_group_window_minutes"
            label="Group window (minutes)"
            inputMode="numeric"
            hint="The first alert from an address is sent at once. Further alerts of the same kind from it are counted for this many minutes, and one summary follows when the time is up, with the count and, for WAF blocks, the categories. From 1 to 1440."
          />
          <TextField
            form={form}
            setting="notify_max_per_hour"
            label="Alerts per channel per hour"
            inputMode="numeric"
            hint="Each channel sends at most this many in any hour, summaries included. Past it the channel holds the rest and, once the hour allows, sends one message saying how many it held. From 1 to 1000."
          />
        </div>
        <p data-testid="limits-memory" className="mt-4 text-sm text-ink-muted">
          The counts are kept in memory: a restart sends the pending summaries first, a crash loses them.
        </p>
      </Section>

      <Section
        level={3}
        title="Channels"
        description="A channel is used once all of its settings are saved. Addresses on this host or inside the proxy stack are refused; LAN, Tailscale and public addresses work."
      >
        <div className="flex flex-col gap-5">
          {CHANNELS.map((c) => (
            <div key={c.id} className="flex flex-col gap-3 border-t border-line-subtle pt-4 first:border-t-0 first:pt-0">
              <div className="flex flex-wrap items-center gap-2">
                <h4 className="text-sm font-semibold text-ink">{c.name}</h4>
                <Badge tone={ready.has(c.name) ? 'success' : 'neutral'}>
                  {ready.has(c.name) ? 'Ready' : 'Not set up'}
                </Badge>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                {c.fields.map((f) => <SecretRow key={f.key} form={form} setting={f.key} label={f.label} placeholder={f.placeholder} />)}
              </div>
              {c.note && <p className="text-sm leading-5 text-ink-muted">{c.note}</p>}
            </div>
          ))}
        </div>
      </Section>

      <Section level={3} title="Test">
        <TestAlert unsaved={unsaved} enabled={form.stored.enable_notifications === 'true'} />
      </Section>
    </div>
  );
}
