// Adversarial bench/latency plane (issue #200, Phase 3).
//
// Generates benign GET load and measures latency percentiles + throughput.
// run.sh invokes this twice via docker compose:
//   - baseline: TARGET=http://mock-upstream/bench          (direct to upstream)
//   - proxied:  TARGET=http://upstream.test/bench + HTTP_PROXY=proxy:3128
//               (through the real Squid + WAF/ICAP path)
// The delta is the proxy + ICAP inspection overhead.
//
// Each request uses a unique cache-buster query so the WAF safe-cache and Squid
// cache both MISS — i.e. we measure real per-request inspection, not cache hits.
//
// Thresholds are the regression gate: k6 exits non-zero if p95 latency or the
// error rate breach them. Tunable via env (P95_MS, MAX_FAIL, VUS, DURATION).
import http from 'k6/http';

const TARGET = __ENV.TARGET || 'http://upstream.test/bench';

export const options = {
  scenarios: {
    load: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS || 10),
      duration: __ENV.DURATION || '15s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<' + (__ENV.MAX_FAIL || '0.05')],
    http_req_duration: ['p(95)<' + (__ENV.P95_MS || '800')],
  },
  // Keep the end-of-test stdout summary compact; the machine-readable numbers
  // come from --summary-export (see run.sh).
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

export default function () {
  http.get(`${TARGET}?i=${__VU}x${__ITER}`);
}
