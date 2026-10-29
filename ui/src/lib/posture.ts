/**
 * One model for how serious a state of the running configuration is, used by
 * Settings, Overview ("Needs attention", lib/attention) and Analytics,
 * Protection coverage (components/analytics/coverage). The two used to judge
 * the same condition apart: alerts switched off were an orange "attention"
 * on one page and a grey "for information" on the other.
 *
 * - needs-attention: it stops clients, or it gives a false sense of safety
 *   (a password never changed, alerts on that go nowhere, a WAF that refuses
 *   the backend).
 * - worth-knowing: a deliberate choice that has a cost (HTTPS not inspected,
 *   alerts off, proxy login off, an empty list).
 * - on: switched on and working.
 * - unknown: the value could not be read.
 */
export type Posture = 'needs-attention' | 'worth-knowing' | 'on' | 'unknown';

/** The state in words, said with every mark (never colour alone). */
export const POSTURE_WORD: Record<Posture, string> = {
  'needs-attention': 'Needs attention',
  'worth-knowing': 'Worth knowing',
  on: 'On',
  unknown: 'Unknown',
};

/**
 * The conditions both pages report, with their one severity. A page that
 * reports one of these takes its severity from here, so the two cannot
 * drift apart again (posture.test.ts checks both read it).
 */
export const SHARED_SEVERITY = {
  httpsOff: 'worth-knowing',
  proxyLoginOff: 'worth-knowing',
  alertsOff: 'worth-knowing',
  alertsWithoutChannel: 'needs-attention',
  proxyLoginWithoutCredentials: 'needs-attention',
} as const satisfies Record<string, Posture>;
