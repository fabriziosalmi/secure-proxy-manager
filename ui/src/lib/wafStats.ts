import axios from 'axios';
import { getData } from './api';
import type { WafStats, WafStatus } from '../types';

/** The WAF's figures, or why there are none, in the words of dashboard/summary's waf_status. */
export interface WafReading {
  waf: WafStats | null;
  waf_status: WafStatus;
}

const REASONS: readonly WafStatus[] = ['auth_failed', 'unreachable', 'error'];

/**
 * GET /api/waf/stats. A failure answers 502 or 503 with waf_status saying
 * why (backend-go/internal/handlers/analytics.go, WAFStats); that reason is
 * returned as a reading, not thrown. Any other failure is thrown, so the
 * caller says the backend did not answer.
 */
export async function readWafStats(): Promise<WafReading> {
  try {
    return { waf: await getData<WafStats>('waf/stats'), waf_status: 'ok' };
  } catch (err) {
    const reason = axios.isAxiosError(err) ? (err.response?.data as { waf_status?: WafStatus } | undefined)?.waf_status : undefined;
    if (reason && REASONS.includes(reason)) return { waf: null, waf_status: reason };
    throw err;
  }
}
