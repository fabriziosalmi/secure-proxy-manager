import { formatCount } from './format';

/**
 * POST /api/maintenance/reload-dns writes every list again. Its data says what
 * the export gave the DNS sinkhole, counted while it wrote the file:
 * `domains` entries sent and `left_out` entries the allowed list took out
 * (backend-go/internal/handlers/maintenance.go, ReloadDNS). The answer used to
 * be COUNT(*) of the table, so a name on Allowed domains was counted as sent.
 */
export interface ListResend {
  domains?: number;
  left_out?: number;
}

/** "640,926 domain entries went to the DNS sinkhole, 3 left out by Allowed domains." */
export function describeListResend(data: ListResend | undefined): string {
  const sent = data?.domains;
  if (typeof sent !== 'number') return 'The lists were written again.';
  const out = data?.left_out;
  const left = typeof out === 'number' && out > 0 ? `, ${formatCount(out)} left out by Domain exceptions` : '';
  return `${formatCount(sent)} domain ${sent === 1 ? 'entry' : 'entries'} went to the DNS sinkhole${left}.`;
}

/** The DNS sinkhole rereads on a trigger and the proxy polls its files: neither answers back. */
export const RESEND_UNCONFIRMED = 'The DNS sinkhole and the proxy reread them within a few seconds; this page cannot confirm it.';
