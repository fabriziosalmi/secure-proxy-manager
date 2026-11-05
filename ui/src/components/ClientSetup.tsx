import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Monitor, Smartphone, Apple, Terminal, Server, Copy, Check, Download } from 'lucide-react';
import toast from 'react-hot-toast';
import { clientSetupQuery, pacFileQuery } from '../lib/queries';
import { PROXY_PORT, cn, proxyEndpoints } from '../lib/utils';
import { Notice } from './ui/Notice';
import { Button } from './ui/Button';

interface OSTab {
  id: string;
  icon: typeof Monitor;
  label: string;
  steps: string[];
  cmd?: string;
  /** Configuration snippets, each for one file and with its own copy button. */
  blocks?: { title: string; file: string; note?: string; cmd: string }[];
  /** How this system trusts the CA certificate, shown when SSL inspection is on. */
  ca: string[];
}

function CodeBlock({ text, label, copied, onCopy }: { text: string; label: string; copied: string; onCopy: (text: string, label: string) => void }) {
  return (
    <div className="relative">
      <pre className="bg-surface-muted border border-line rounded-control p-3 pr-9 text-xs font-mono text-ink overflow-x-auto whitespace-pre-wrap break-all">
        {text}
      </pre>
      <button
        type="button"
        onClick={() => onCopy(text, label)}
        aria-label={`Copy ${label}`}
        className="absolute top-2 right-2 p-1 rounded-control border border-line bg-surface text-ink-muted hover:bg-surface-muted hover:text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
      >
        {copied === label ? <Check aria-hidden="true" className="w-3.5 h-3.5 text-success" /> : <Copy aria-hidden="true" className="w-3.5 h-3.5" />}
      </button>
    </div>
  );
}

function CopyBtn({ text, label, copied, onCopy }: { text: string; label: string; copied: string; onCopy: (text: string, label: string) => void }) {
  return (
    <button
      type="button"
      onClick={() => onCopy(text, label)}
      aria-label={`Copy ${label}`}
      className="p-1 rounded-control text-ink-muted hover:bg-surface-muted hover:text-ink transition-colors shrink-0 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
    >
      {copied === label ? <Check aria-hidden="true" className="w-3.5 h-3.5 text-success" /> : <Copy aria-hidden="true" className="w-3.5 h-3.5" />}
    </button>
  );
}

/**
 * How to point a device at the proxy. The same component runs in the
 * dashboard and on the /setup page, which has no session: everything it reads
 * comes from GET /api/client-setup, which needs no login.
 */
export function ClientSetup() {
  const [copied, setCopied] = useState('');
  const setup = useQuery(clientSetupQuery);
  const pac = useQuery(pacFileQuery);
  const proxy = proxyEndpoints(setup.data?.proxy_ip);
  const host = proxy.host;
  const proxyPort = String(PROXY_PORT);
  const proxyAddr = proxy.address;
  const proxyAuthOn = setup.data?.proxy_auth ?? false;
  const bump = setup.data?.inspection === 'bump';
  const ca = setup.data?.ca ?? null;

  const copyTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const copy = async (text: string, label: string) => {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error('Clipboard unavailable');
      }
      await navigator.clipboard.writeText(text);
      setCopied(label);
      toast.success(`Copied ${label}`);
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(''), 2000);
    } catch {
      toast.error('Clipboard access denied');
    }
  };
  useEffect(() => () => { if (copyTimer.current) clearTimeout(copyTimer.current); }, []);

  const downloadPAC = () => {
    if (pac.data === undefined) return;
    const blob = new Blob([pac.data], { type: 'application/x-ns-proxy-autoconfig' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'proxy.pac'; a.click();
    URL.revokeObjectURL(url);
    toast.success('PAC file downloaded');
  };

  // The proxy speaks plain HTTP, also for HTTPS sites (CONNECT): every URL below is http://.
  const proxyURL = `http://${proxyAddr}`; // slopless-disable-line VBC-034 -- the proxy URL is http:// for every client; https would break them
  const lanBypass = 'localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16';
  const caURL = `http://${host}/ca.crt`; // slopless-disable-line VBC-034 -- nginx serves the CA on port 80 too: the device does not trust this server's HTTPS yet
  const linuxCA = [
    `Debian and Ubuntu: sudo curl -fsSo /usr/local/share/ca-certificates/secure-proxy-ca.crt ${caURL} && sudo update-ca-certificates`,
    'Compare its fingerprint with the one above before you trust it: openssl x509 -in /usr/local/share/ca-certificates/secure-proxy-ca.crt -noout -fingerprint -sha256',
  ];

  const tabs: OSTab[] = [
    {
      id: 'windows', icon: Monitor, label: 'Windows',
      steps: [
        'Open Settings → Network & Internet → Proxy',
        'Enable "Use a proxy server"',
        `Address: ${host}`,
        `Port: ${proxyPort}`,
        'Check "Don\'t use proxy for local addresses"',
        'Click Save',
      ],
      cmd: `netsh winhttp set proxy ${proxyAddr}`,
      ca: [
        'Open secure-proxy-ca.crt → Install Certificate → Local Machine',
        'Place all certificates in the following store → Trusted Root Certification Authorities → Finish',
      ],
    },
    {
      id: 'macos', icon: Apple, label: 'macOS',
      steps: [
        'Open System Settings → Network → Wi-Fi → Details → Proxies',
        'Enable "Web Proxy (HTTP)"',
        `Server: ${host}, Port: ${proxyPort}`,
        'Enable "Secure Web Proxy (HTTPS)" with same settings',
        'Click OK → Apply',
      ],
      cmd: `networksetup -setwebproxy Wi-Fi ${host} ${proxyPort}\nnetworksetup -setsecurewebproxy Wi-Fi ${host} ${proxyPort}`,
      ca: [
        'Open secure-proxy-ca.crt: Keychain Access adds it to the System keychain',
        'Double-click the certificate → Trust → When using this certificate: Always Trust',
      ],
    },
    {
      id: 'linux', icon: Terminal, label: 'Linux',
      steps: [
        'Add to ~/.bashrc for your shell (for every program, apt and Docker, see Linux server):',
      ],
      cmd: `export http_proxy=${proxyURL}\nexport https_proxy=${proxyURL}\nexport no_proxy=${lanBypass}`,
      ca: linuxCA,
    },
    {
      id: 'linux-server', icon: Server, label: 'Linux server',
      steps: [
        'Programs read the proxy from the environment, apt and the Docker daemon from their own files. Set the ones the server uses.',
        ...(proxyAuthOn ? [`The proxy login is on: write each URL as http://USER:PASSWORD@${proxyAddr}, with the password URL-encoded.`] : []), // slopless-disable-line VBC-034 -- the proxy URL is http:// for every client
      ],
      blocks: [
        {
          title: 'Every program, from the next login',
          file: '/etc/environment',
          note: 'One NAME=value per line, no export. Some programs read only the lowercase names, some only the uppercase ones.',
          cmd: `http_proxy=${proxyURL}\nhttps_proxy=${proxyURL}\nno_proxy=${lanBypass}\nHTTP_PROXY=${proxyURL}\nHTTPS_PROXY=${proxyURL}\nNO_PROXY=${lanBypass}`,
        },
        {
          title: 'apt',
          file: '/etc/apt/apt.conf.d/95proxy',
          cmd: `Acquire::http::Proxy "${proxyURL}";\nAcquire::https::Proxy "${proxyURL}";`,
        },
        {
          title: 'Docker image pulls',
          file: '/etc/systemd/system/docker.service.d/http-proxy.conf',
          note: 'Then: sudo systemctl daemon-reload && sudo systemctl restart docker. Containers do not inherit it; pass the variables to those that need them.',
          cmd: `[Service]\nEnvironment="HTTP_PROXY=${proxyURL}"\nEnvironment="HTTPS_PROXY=${proxyURL}"\nEnvironment="NO_PROXY=localhost,127.0.0.1"`,
        },
        {
          title: 'One systemd service',
          file: 'sudo systemctl edit <service>',
          note: 'Then: sudo systemctl restart <service>. A service does not read /etc/environment.',
          cmd: `[Service]\nEnvironment="HTTP_PROXY=${proxyURL}"\nEnvironment="HTTPS_PROXY=${proxyURL}"\nEnvironment="NO_PROXY=${lanBypass}"`,
        },
      ],
      ca: linuxCA,
    },
    {
      id: 'ios', icon: Smartphone, label: 'iOS',
      steps: [
        'Open Settings → Wi-Fi → tap your network (i)',
        `Scroll to HTTP Proxy → Configure Proxy → Automatic, URL ${proxy.pacURL}; or Manual:`,
        `Server: ${host}`,
        `Port: ${proxyPort}`,
        proxyAuthOn ? 'Authentication: Username and password' : 'Authentication: Off',
      ],
      ca: [
        'Open secure-proxy-ca.crt in Safari → Allow, then Settings → Profile Downloaded → Install',
        'Settings → General → About → Certificate Trust Settings → turn on full trust for it',
      ],
    },
    {
      id: 'android', icon: Smartphone, label: 'Android',
      steps: [
        'Open Settings → Network → Wi-Fi → long-press your network → Modify',
        'Advanced options → Proxy → Manual',
        `Hostname: ${host}`,
        `Port: ${proxyPort}`,
        'Bypass: localhost,127.0.0.1',
      ],
      ca: [
        'Settings → Security → More security settings → Encryption & credentials → Install a certificate → CA certificate, then pick secure-proxy-ca.crt',
        'Browsers trust it; many apps trust only the system certificates and will refuse inspected connections',
      ],
    },
  ];

  const [activeTab, setActiveTab] = useState('windows');
  const active = tabs.find(t => t.id === activeTab)!;

  return (
    <div className="rounded-panel border border-line bg-surface p-4 text-ink">
      <div>
        {/* Proxy address */}
        <div className="flex items-center gap-2 mb-3 px-3 py-2 bg-accent-subtle border border-accent-line rounded-control">
          <span className="text-xs text-ink-muted">Proxy:</span>
          <code className="text-sm font-bold font-mono text-accent">{proxyAddr}</code>
          <CopyBtn text={proxyAddr} label="proxy" copied={copied} onCopy={(t, l) => void copy(t, l)} />
        </div>

        {proxy.loopback && (
          <Notice tone="warning" title="Other devices cannot reach this address" className="mb-3">
            This page is open on {host}, which is this server to itself. A phone or laptop needs the server&apos;s
            address on your network: open the dashboard by that address, or set <code className="font-mono">PROXY_IP</code> in
            <code className="font-mono"> .env</code> to it and restart the backend.
          </Notice>
        )}

        {/* Automatic configuration, as nginx serves it on port 80 */}
        <div className="flex flex-wrap items-center gap-2 mb-3 px-3 py-2 bg-surface-muted border border-line rounded-control">
          <span className="text-xs text-ink-muted">Automatic configuration (PAC) URL:</span>
          <code className="text-xs font-mono text-ink break-all">{proxy.pacURL}</code>
          <CopyBtn text={proxy.pacURL} label="PAC URL" copied={copied} onCopy={(t, l) => void copy(t, l)} />
        </div>

        {/* PAC file download: the file nginx serves, not a copy */}
        <div className="flex flex-wrap gap-2 mb-3">
          <Button size="sm" icon={<Download />} onClick={downloadPAC} disabled={pac.data === undefined}>
            Download PAC File
          </Button>
          <Button size="sm" icon={<Copy />} onClick={() => pac.data !== undefined && void copy(pac.data, 'pac')} disabled={pac.data === undefined}>
            Copy PAC
          </Button>
        </div>
        {pac.isError && (
          <p className="text-xs text-danger mb-3">This server did not serve its PAC file (/wpad.dat), so devices using the PAC URL cannot load it either.</p>
        )}

        {/* The page a device opens without signing in */}
        <div className="flex flex-wrap items-center gap-2 mb-4 px-3 py-2 bg-surface-muted border border-line rounded-control">
          <span className="text-xs text-ink-muted">On the device, without signing in:</span>
          <code className="text-xs font-mono text-ink break-all">{proxy.setupURL}</code>
          <CopyBtn text={proxy.setupURL} label="setup URL" copied={copied} onCopy={(t, l) => void copy(t, l)} />
        </div>

        {bump && (
          <Notice tone="warning" title="This proxy decrypts HTTPS: each device must trust its CA certificate" className="mb-4">
            {ca ? (
              <div className="flex flex-col gap-2">
                <span>
                  Without it, HTTPS sites show certificate errors. Install it only after checking that its SHA-256
                  fingerprint matches the one here.
                </span>
                <code className="text-xs font-mono break-all">{ca.sha256}</code>
                <span className="text-xs">Expires {new Date(ca.not_after).toLocaleDateString()}.</span>
                <div>
                  <Button size="sm" icon={<Download />} onClick={() => { window.location.href = '/ca.crt'; }}>
                    Download CA certificate
                  </Button>
                </div>
              </div>
            ) : (
              <span>The proxy has not created its CA certificate yet. Reload this page after the proxy has restarted.</span>
            )}
          </Notice>
        )}
        {setup.data?.inspection === 'peek' && (
          <p className="text-xs text-ink-muted mb-4">TLS peek is on: the proxy reads the name of each HTTPS site and decrypts nothing, so there is no certificate to install.</p>
        )}

        {/* OS tabs */}
        <div role="tablist" aria-label="Operating system" className="flex flex-wrap gap-1 mb-3 border-b border-line pb-2">
          {tabs.map((t, i) => {
            const Icon = t.icon;
            const selected = activeTab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                role="tab"
                id={`os-tab-${t.id}`}
                aria-selected={selected}
                aria-controls="os-panel"
                tabIndex={selected ? 0 : -1}
                onClick={() => setActiveTab(t.id)}
                onKeyDown={(e) => {
                  if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
                  e.preventDefault();
                  const dir = e.key === 'ArrowRight' ? 1 : -1;
                  const next = tabs[(i + dir + tabs.length) % tabs.length];
                  setActiveTab(next.id);
                  document.getElementById(`os-tab-${next.id}`)?.focus();
                }}
                className={cn(
                  'flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-control border transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
                  selected
                    ? 'border-accent-line bg-accent-subtle text-accent font-semibold'
                    : 'border-transparent text-ink-muted hover:bg-surface-muted hover:text-ink',
                )}
              >
                <Icon aria-hidden="true" className="w-3.5 h-3.5" /> {t.label}
              </button>
            );
          })}
        </div>

        <div role="tabpanel" id="os-panel" aria-labelledby={`os-tab-${active.id}`}>
          {/* Steps */}
          <ol className="space-y-1.5 mb-3">
            {active.steps.map((step, i) => (
              <li key={i} className="flex gap-2 text-xs text-ink-secondary">
                <span className="text-ink-muted font-semibold shrink-0">{i + 1}.</span>
                <span>{step}</span>
              </li>
            ))}
          </ol>

          {bump && ca && (
            <>
              <p className="text-xs font-semibold text-ink mb-1.5">Trust the CA certificate</p>
              <ol className="space-y-1.5 mb-3">
                {active.ca.map((step, i) => (
                  <li key={i} className="flex gap-2 text-xs text-ink-secondary">
                    <span className="text-ink-muted font-semibold shrink-0">{i + 1}.</span>
                    <span className="break-all">{step}</span>
                  </li>
                ))}
              </ol>
            </>
          )}

          {/* Command */}
          {active.cmd && <CodeBlock text={active.cmd} label="command" copied={copied} onCopy={(t, l) => void copy(t, l)} />}

          {active.blocks?.map((b) => (
            <div key={b.file} className="mt-3 flex flex-col gap-1.5">
              <p className="text-xs text-ink-secondary">
                <span className="font-semibold text-ink">{b.title}</span>: <code className="font-mono break-all">{b.file}</code>
              </p>
              <CodeBlock text={b.cmd} label={`${b.title} configuration`} copied={copied} onCopy={(t, l) => void copy(t, l)} />
              {b.note && <p className="text-xs text-ink-muted">{b.note}</p>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
