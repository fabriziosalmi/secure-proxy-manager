/**
 * Inspection: HTTPS inspection with its certificate authority, the six WAF
 * heuristics with what the running WAF applies, the WAF policy (log-only
 * rules and exceptions, WafPolicySection) and the pattern tester.
 *
 * The heuristics are stored values pushed to the WAF on save and by the
 * backend's reconciler; GET /api/waf/heuristics says what the WAF runs now,
 * which differs while INTERNAL_ALERT_TOKEN is missing or the WAF is down.
 * The texts come from waf-go/internal/engine/heuristics.go.
 */
import axios from 'axios';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Download } from 'lucide-react';
import { api, getData, getErrorMessage } from '../../../lib/api';
import { Section } from '../../ui/Section';
import { Notice } from '../../ui/Notice';
import { Button } from '../../ui/Button';
import { ToggleRow } from '../fields';
import { RegexPlayground } from '../../RegexPlayground';
import { WafPolicySection } from './WafPolicySection';
import type { SectionForm } from '../sectionForm';

function Code({ children }: { children: string }) {
  return <code className="rounded bg-surface-muted px-1 py-px font-mono text-[12px] text-ink">{children}</code>;
}

const HEURISTICS: { key: string; label: string; help: string }[] = [
  { key: 'waf_h_entropy', label: 'Entropy detection', help: 'Scores a request body over 256 bytes, or a URL, whose entropy is above 7.5 (WAF_H_ENTROPY_MAX): data that looks encrypted or compressed leaving the network. Adds 6 for a body, 7 for a URL.' },
  { key: 'waf_h_beaconing', label: 'Beaconing', help: 'Scores a client that makes at least 5 requests in 5 minutes at regular intervals with payloads of nearly the same size, the pattern of malware checking in with its controller. Adds 6.' },
  { key: 'waf_h_pii', label: 'Personal data in responses', help: 'Scores a response that carries more than 5 email addresses, card-like numbers or US social security numbers. Adds 10.' },
  { key: 'waf_h_sharding', label: 'Destination sharding', help: 'Scores a client that contacts more than 50 different destinations within a minute. Adds 6.' },
  { key: 'waf_h_ghosting', label: 'Protocol ghosting', help: 'Scores a request body that starts like SSH, SMTP, a Linux (ELF) or a Windows (PE) executable. Adds 7.' },
  { key: 'waf_h_sequence', label: 'Sequence validation', help: 'Scores a POST to a /login path that does not follow a GET, and a DELETE that follows anything but a GET. Adds 7. Off in the shipped compose.' },
];

interface RunningHeuristics { available: boolean; running?: Record<string, boolean>; reason?: string }

const wafHeuristicsQuery = {
  queryKey: ['waf', 'heuristics'] as const,
  queryFn: () => getData<RunningHeuristics>('waf/heuristics'),
};

const OS_STEPS: { os: string; steps: string[] }[] = [
  { os: 'Windows', steps: ['In an administrator command prompt, in the folder with the file:', 'certutil -addstore -f Root secure-proxy-ca.pem'] },
  { os: 'macOS', steps: ['In Terminal, in the folder with the file:', 'sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain secure-proxy-ca.pem'] },
  { os: 'Debian and Ubuntu', steps: ['The file must end in .crt in that folder:', 'sudo cp secure-proxy-ca.pem /usr/local/share/ca-certificates/secure-proxy-ca.crt && sudo update-ca-certificates'] },
  { os: 'Fedora and RHEL', steps: ['sudo cp secure-proxy-ca.pem /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust'] },
  { os: 'iOS and iPadOS', steps: ['Send the file to the device (AirDrop or mail) and open it, then install it in Settings, General, VPN and Device Management.', 'Then turn it on in Settings, General, About, Certificate Trust Settings.'] },
  { os: 'Android', steps: ['Settings, Security, Encryption and credentials, Install a certificate, CA certificate, then pick the file.', 'Chrome trusts it. Apps built for Android 7 or later do not trust a CA the user installed, so they fail while inspection is on.'] },
  { os: 'Firefox', steps: ['Firefox keeps its own list: Settings, Privacy and Security, Certificates, View Certificates, Authorities, Import, then trust it for websites.'] },
];

type CaState = { kind: 'idle' | 'busy' } | { kind: 'done' } | { kind: 'failed'; message: string };

function CertificateAuthority() {
  const [state, setState] = useState<CaState>({ kind: 'idle' });
  const download = async () => {
    setState({ kind: 'busy' });
    try {
      const res = await api.get('security/download-ca', { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.download = 'secure-proxy-ca.pem';
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setState({ kind: 'done' });
    } catch (err) {
      // The proxy writes its CA at every start, whatever the switch says
      // (generate_squid_conf.sh); the backend answers 404 until it has.
      const missing = axios.isAxiosError(err) && err.response?.status === 404;
      setState({
        kind: 'failed',
        message: missing
          ? 'The proxy has not created its certificate authority yet. It creates one each time the proxy container starts: start the proxy, then download again.'
          : `The download failed: ${getErrorMessage(err, 'the backend did not answer')}.`,
      });
    }
  };
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm leading-6 text-ink-secondary">
        The proxy signs the sites it inspects with its own certificate authority. Each device must trust it, or every HTTPS site shows a
        certificate error while inspection is on.
      </p>
      <div>
        <Button icon={<Download />} onClick={() => void download()} disabled={state.kind === 'busy'}>
          {state.kind === 'busy' ? 'Downloading...' : 'Download the CA certificate (.pem)'}
        </Button>
      </div>
      <div role="status" className="text-sm">
        {state.kind === 'done' && <p className="text-success">Downloaded secure-proxy-ca.pem.</p>}
        {state.kind === 'failed' && <p className="text-danger">{state.message}</p>}
      </div>
      <div className="flex flex-col gap-2">
        {OS_STEPS.map((o) => (
          <details key={o.os} className="rounded-control border border-line px-3 py-2">
            <summary className="cursor-pointer text-sm font-semibold text-ink">{o.os}</summary>
            <div className="mt-2 flex flex-col gap-1.5">
              {o.steps.map((s) => (
                /^(sudo|certutil) /.test(s)
                  ? <pre key={s} className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-surface-muted px-2 py-1.5 font-mono text-[12px] text-ink">{s}</pre>
                  : <p key={s} className="text-sm text-ink-secondary">{s}</p>
              ))}
            </div>
          </details>
        ))}
      </div>
    </div>
  );
}

function RunningState({ stored, running }: { stored: boolean; running: boolean | undefined }) {
  if (running === undefined) return null;
  return (
    <p className="text-xs text-ink-muted">
      The WAF runs it <span className="font-semibold">{running ? 'on' : 'off'}</span>
      {running !== stored && ', not as saved here'}.
    </p>
  );
}

export function InspectionSection({ form }: { form: SectionForm }) {
  const v = form.values;
  const turningOn = v.ssl_bump_enabled === 'true' && form.stored.ssl_bump_enabled !== 'true';
  const waf = useQuery(wafHeuristicsQuery);
  const running = waf.data?.available ? waf.data.running : undefined;

  return (
    <div className="flex flex-col gap-4">
      <Section level={3} title="HTTPS inspection">
        <ToggleRow
          form={form}
          setting="ssl_bump_enabled"
          label="Inspect HTTPS traffic"
          help="Without it, HTTPS passes as an encrypted tunnel: the WAF, the download filter and the cache see only the destination name. With it, the proxy decrypts each request with its own certificate authority."
        />
        {turningOn && (
          <Notice tone="warning" title="Every device must trust the proxy's CA before you save" className="mt-3">
            A device without it gets a certificate error on every HTTPS site.
          </Notice>
        )}
        {v.proxy_port && v.proxy_port !== '3128' && v.ssl_bump_enabled === 'true' && (
          <Notice tone="warning" title="Inspection does not reach this port" className="mt-3">
            The proxy turns inspection on for its listener on port 3128 only, and the stored proxy port is {v.proxy_port}.
          </Notice>
        )}
        <div className="mt-4 border-t border-line-subtle pt-4">
          <CertificateAuthority />
        </div>
      </Section>

      <Section
        level={3}
        title="WAF heuristics"
        description="Each one adds to a request's score. The WAF blocks at WAF_BLOCK_THRESHOLD in .env, 10 in the shipped compose, so most need a second signal to block."
      >
        {waf.isSuccess && waf.data && !waf.data.available && (
          <Notice tone="warning" title="The running WAF could not be asked what it applies" className="mb-3">
            {waf.data.reason ?? 'No reason was given'}. The values below are the saved ones.
          </Notice>
        )}
        {waf.isError && (
          <Notice tone="warning" title="GET /api/waf/heuristics failed" className="mb-3">
            The values below are the saved ones; what the WAF runs is not known.
          </Notice>
        )}
        {HEURISTICS.map((h) => (
          <div key={h.key}>
            <ToggleRow form={form} setting={h.key} label={h.label} help={h.help} />
            <RunningState stored={form.stored[h.key] === 'true'} running={running?.[h.key]} />
          </div>
        ))}
      </Section>

      <WafPolicySection />

      <Section level={3} title="Test a pattern" description="Against the URLs of recent requests in the log.">
        <CustomPatterns />
        <RegexPlayground />
      </Section>
    </div>
  );
}

interface WafCategory { name: string; rules: number; enabled: boolean }

/** How many custom patterns the WAF loaded, from GET /api/waf/categories. */
function CustomPatterns() {
  const cats = useQuery({
    queryKey: ['waf', 'categories'],
    // A WAF that is down answers 502 here; the line below says so, so the
    // failure is an answer, not an app-wide "failed to load" toast.
    queryFn: () => api.get('waf/categories')
      .then((r) => (Array.isArray(r.data?.data) ? (r.data.data as WafCategory[]) : null))
      .catch(() => null),
    retry: false,
  });
  let loaded: string;
  if (cats.isPending) loaded = 'Asking the WAF which custom patterns it loaded...';
  else if (cats.isError || !cats.data) loaded = 'The WAF could not be asked which custom patterns it loaded.';
  else {
    const custom = cats.data.find((c) => c.name === 'CUSTOM_USER_RULES');
    loaded = custom ? `The WAF loaded ${custom.rules === 1 ? '1 custom pattern' : `${custom.rules} custom patterns`}${custom.enabled ? '' : ', and that category is off'}.` : 'The WAF loaded no custom pattern.';
  }
  return (
    <div className="mb-4 flex flex-col gap-1.5 text-sm leading-6 text-ink-secondary">
      <p>
        Custom patterns are read from <Code>/config/waf_custom_rules.txt</Code>, one regular expression per line, matched without regard to
        case, when the WAF starts; this page cannot edit that file. Each match adds 7 to a request's score.
      </p>
      <p>{loaded}</p>
    </div>
  );
}
