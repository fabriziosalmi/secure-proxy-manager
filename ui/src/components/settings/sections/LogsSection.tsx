/**
 * Logs and privacy: how long requests are kept (workers/log_retention.go:
 * once when the backend starts, then every 24 hours, proxy_logs only; the
 * audit log has its own 365 days) and what client IP masking covers. gdpr_mode
 * masks client addresses everywhere they leave the backend (all API responses,
 * the live feed, CSV export, MCP tools, and alerts), while the SQLite database
 * and /api/database/export keep the full addresses.
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
          label="Mask client IPs"
          help="Masks client addresses everywhere they leave the backend: all API endpoints (the Logs table, CSV export and live feed, the Clients page grouped by network, and the Overview), MCP tools, and WAF alerts. IPv4 is masked to /24 (192.168.1.x) and IPv6 down to /64 (2001:db8:1:2::x). The SQLite database and its full export (/api/database/export) are not masked and keep the full addresses."
        />
      </Section>
    </div>
  );
}
