/**
 * Logs and privacy: how long requests are kept (workers/log_retention.go:
 * once when the backend starts, then every 24 hours, proxy_logs only; the
 * audit log has its own 365 days), what client IP masking covers, and log
 * forwarding to a syslog server or SIEM (internal/logforward). gdpr_mode
 * masks client addresses everywhere they leave the backend (all API
 * responses, the live feed, CSV export, MCP tools, alerts and forwarded
 * logs), while the SQLite database and /api/database/export keep the full
 * addresses.
 */
import { useState } from 'react';
import { api, getErrorMessage } from '../../../lib/api';
import { Section } from '../../ui/Section';
import { Notice } from '../../ui/Notice';
import { Button } from '../../ui/Button';
import { ChoiceRow, TextField, ToggleRow } from '../fields';
import type { SectionForm } from '../sectionForm';

type TestState =
  | { kind: 'idle' }
  | { kind: 'busy' }
  | { kind: 'sent'; note: string; target: string }
  | { kind: 'failed'; message: string };

/** POST /api/log-forward/test: one test event to the saved target. */
function TestForward({ unsaved }: { unsaved: number }) {
  const [state, setState] = useState<TestState>({ kind: 'idle' });
  const send = async () => {
    setState({ kind: 'busy' });
    try {
      const res = await api.post('log-forward/test', {});
      const data = (res.data?.data ?? {}) as { note?: string; target?: string };
      setState({ kind: 'sent', note: data.note ?? '', target: data.target ?? '' });
    } catch (err) {
      setState({ kind: 'failed', message: getErrorMessage(err, 'the backend did not answer') });
    }
  };
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={() => void send()} disabled={state.kind === 'busy' || unsaved > 0}>
          {state.kind === 'busy' ? 'Sending...' : 'Send a test event'}
        </Button>
        <p className="text-sm text-ink-muted">
          {unsaved > 0
            ? 'Save or discard the changes first: the test uses the saved target.'
            : 'Sends one event to the saved target now, whether forwarding is on or not.'}
        </p>
      </div>
      <div aria-live="polite">
        {state.kind === 'sent' && <Notice tone="info" title={`Sent to ${state.target}`}>{state.note}</Notice>}
        {state.kind === 'failed' && <Notice tone="danger" title="The test event did not go">{state.message}.</Notice>}
      </div>
    </div>
  );
}

export function LogsSection({ form, unsaved = 0 }: { form: SectionForm; unsaved?: number }) {
  return (
    <div className="flex flex-col gap-4">
      <Section level={3} title="Retention">
        <TextField
          form={form}
          setting="log_retention_days"
          label="Keep logs for (days)"
          inputMode="numeric"
          className="sm:max-w-[240px]"
          hint="When the backend starts and then every 24 hours, requests older than this are deleted. The Logs, Clients and Overview figures are worked out from these requests, so they reach back at most this far. The audit log is kept for 365 days, whatever this says."
        />
      </Section>
      <Section level={3} title="Privacy">
        <ToggleRow
          form={form}
          setting="gdpr_mode"
          label="Mask client IPs"
          help="Masks client addresses everywhere they leave the backend: all API endpoints (the Logs table, CSV export and live feed, the Clients page grouped by network, and the Overview), MCP tools, WAF alerts and forwarded logs. IPv4 is masked to /24 (192.168.1.x) and IPv6 down to /64 (2001:db8:1:2::x). The SQLite database and its full export (/api/database/export) are not masked and keep the full addresses."
        />
      </Section>
      <Section level={3} title="Forward to a syslog server or SIEM">
        <ToggleRow
          form={form}
          setting="log_forward_enabled"
          label="Forward logs"
          help="Sends each request the proxy logs, and each admin action, as it is recorded. Events wait in a queue of 10,000 while the target is slow or down and are sent when it is back; past that, new events are dropped and counted (spm_log_forward_events_total on /metrics)."
        />
        <div className="grid gap-4 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <TextField
            form={form}
            setting="log_forward_host"
            label="Host"
            placeholder="e.g. siem.example.internal"
            hint="An IP address or a host name, without a scheme or a port."
          />
          <TextField form={form} setting="log_forward_port" label="Port" inputMode="numeric" hint="514 for UDP and TCP, 6514 for TLS, by convention." />
        </div>
        <ChoiceRow
          form={form}
          setting="log_forward_protocol"
          label="Protocol"
          help="UDP has no answer, so an event lost on the way is not known. TCP and TLS keep a connection, and TLS checks the target's certificate against the system's roots."
          options={[{ value: 'udp', label: 'UDP' }, { value: 'tcp', label: 'TCP' }, { value: 'tls', label: 'TLS' }]}
        />
        <ChoiceRow
          form={form}
          setting="log_forward_format"
          label="Format"
          help="Syslog (RFC 5424, facility local0) with the fields as key=value pairs, or one JSON object per event. Over TCP and TLS a syslog message is prefixed with its length (RFC 6587), a JSON object ends with a newline."
          options={[{ value: 'rfc5424', label: 'Syslog' }, { value: 'json', label: 'JSON' }]}
        />
        <ChoiceRow
          form={form}
          setting="log_forward_events"
          label="Requests to send"
          help="Blocked requests only, every request, or none (audit events only)."
          options={[{ value: 'blocked', label: 'Blocked' }, { value: 'all', label: 'All' }, { value: 'none', label: 'None' }]}
        />
        <ToggleRow
          form={form}
          setting="log_forward_audit"
          label="Admin audit events"
          help="Sign-ins, setting changes, list edits: what the audit log records, as it records it."
        />
        <TextField
          form={form}
          setting="log_forward_hostname"
          label="Host name in each event"
          placeholder="e.g. proxy-1.lan"
          className="sm:max-w-[320px]"
          hint="How the target tells this proxy apart from other senders. Empty sends secure-proxy-manager."
        />
        <TestForward unsaved={unsaved} />
      </Section>
    </div>
  );
}
