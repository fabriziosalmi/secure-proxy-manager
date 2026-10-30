// Transport baseline: latency and throughput of one request
// shape through the proxy, with ICAP on or off (the proxy's configuration,
// set by transport.sh), or straight to the upstream.
//
// Env: TARGET (URL), METHOD (GET or POST), BODY_BYTES (POST body size),
// VUS, DURATION, SUMMARY_PATH. Every request carries a unique query, so
// neither Squid's cache nor the WAF's safe-URL cache answers it.
import http from 'k6/http';
import { Counter } from 'k6/metrics';

// Responses by HTTP status (0 = no response at all), declared up front as k6
// requires, so a failure rate says who failed: the proxy, the upstream or
// the connection. The first failures of each VU are also printed.
const STATUSES = [0, 200, 400, 403, 404, 405, 411, 413, 500, 502, 503, 504];
const byStatus = Object.fromEntries(STATUSES.map((c) => [c, new Counter(`status_${c}`)]));
const statusOther = new Counter('status_other');
let printed = 0;

const TARGET = __ENV.TARGET || 'http://upstream.test/bench';
const METHOD = __ENV.METHOD || 'GET';
const BODY_BYTES = Number(__ENV.BODY_BYTES || 0);

// Benign prose, repeated to size: the body is something a person could post,
// so a rule that fires on it is a finding, not a property of the bench.
const PROSE = 'The quarterly report covers deliveries, staffing and the new depot opening in spring. ';
const BODY = BODY_BYTES > 0 ? PROSE.repeat(Math.ceil(BODY_BYTES / PROSE.length)).slice(0, BODY_BYTES) : null;

export const options = {
  scenarios: {
    load: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS || 10),
      duration: __ENV.DURATION || '30s',
    },
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

// Every URL is unique (no cache answers for us), so every request carries
// the same name tag: k6 keeps one metric series per name, and with the URL as
// the name it kept one per request, 800,000 after 3 minutes, until it was
// killed for memory.
const tags = { name: 'bench' };

export default function () {
  const url = `${TARGET}?i=${__VU}x${__ITER}`;
  const res = METHOD === 'POST'
    ? http.post(url, BODY, { headers: { 'Content-Type': 'text/plain' }, tags })
    : http.get(url, { tags });
  (byStatus[res.status] || statusOther).add(1);
  if ((res.status === 0 || res.status >= 400) && printed < 3) {
    printed++;
    console.warn(`VU ${__VU}: status ${res.status} error_code ${res.error_code} ${res.error || ''}`);
  }
}

export function handleSummary(data) {
  const flat = {};
  for (const [name, metric] of Object.entries(data.metrics || {})) {
    flat[name] = { ...(metric.values || {}) };
  }
  const out = {};
  out[__ENV.SUMMARY_PATH || '/report/transport-summary.json'] = JSON.stringify({ metrics: flat }, null, 2);
  return out;
}
