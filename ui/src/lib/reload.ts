import axios from 'axios';
import { api, getErrorMessage } from './api';
import { formatClock } from './format';

/**
 * What POST /api/maintenance/reload-config says the proxy did. The backend
 * writes a trigger and waits up to 8 seconds for the proxy's watchdog:
 * 200 success = the new configuration is live, 200 pending = nothing
 * answered in time, 500 reload_failed = the proxy refused it and kept the
 * previous one (docs/api/settings.md).
 */
export type ApplyOutcome =
  | { kind: 'applied'; at: Date }
  | { kind: 'pending' }
  | { kind: 'refused'; generatorRc?: number; reconfigureRc?: number | null }
  | { kind: 'failed'; message: string };

export async function applyToProxy(): Promise<ApplyOutcome> {
  try {
    const res = await api.post('maintenance/reload-config', {});
    if (res.data?.status === 'pending') return { kind: 'pending' };
    return { kind: 'applied', at: new Date() };
  } catch (err) {
    if (axios.isAxiosError(err) && err.response?.data?.code === 'reload_failed') {
      const d = err.response.data.data ?? {};
      return { kind: 'refused', generatorRc: d.generator_rc, reconfigureRc: d.reconfigure_rc };
    }
    return { kind: 'failed', message: getErrorMessage(err, 'the backend did not answer') };
  }
}

/**
 * One sentence for an outcome, as the page shows it. done names what
 * already happened before the reload ("Saved", "Restored").
 */
export function describeApply(o: ApplyOutcome, done = 'Saved'): { tone: 'success' | 'warning' | 'danger'; text: string } {
  switch (o.kind) {
    case 'applied':
      return { tone: 'success', text: `Applied to the proxy at ${formatClock(o.at)}.` };
    case 'pending':
      return { tone: 'warning', text: `${done}. The proxy did not confirm within 8 seconds: check that the proxy container is running.` };
    case 'refused': {
      const rc = o.generatorRc ? ` (generator exit code ${o.generatorRc})` : o.reconfigureRc ? ` (reconfigure exit code ${o.reconfigureRc})` : '';
      return { tone: 'danger', text: `${done}, but the proxy refused the new configuration and kept the previous one${rc}.` };
    }
    case 'failed':
      return { tone: 'danger', text: `${done}, but the proxy reload could not be requested: ${o.message}.` };
  }
}
