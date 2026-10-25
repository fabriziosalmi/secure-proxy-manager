/**
 * Logs and privacy: how long requests are kept (workers/log_retention.go:
 * once when the backend starts, then every 24 hours, proxy_logs only; the
 * audit log has its own 365 days) and what the log viewer shows. gdpr_mode
 * masks source_ip in GET /api/logs and in the live feed (/api/ws/logs), the
 * two the Logs page reads, and nothing else.
 */
import { Section } from '../../ui/Section';
import { TextField, ToggleRow } from '../fields';
import type { SectionForm } from '../sectionForm';

export function LogsSection({ form }: { form: SectionForm }) {
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
          label="Mask client IPs in the log viewer"
          help="The Logs page, its table and its live feed, shows each client address with the last part replaced by x (192.168.1.x), within 30 seconds of the save. The stored requests keep the full address, and the rest of the app shows it, the Clients page among them, which tells clients apart by it."
        />
      </Section>
    </div>
  );
}
