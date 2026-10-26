import { useEffect, useRef, useState } from 'react';
import { Monitor, Smartphone, Apple, Terminal, Copy, Check, Download, QrCode } from 'lucide-react';
import toast from 'react-hot-toast';
import { PROXY_PORT, proxyAddress, cn } from '../lib/utils';
import { Button } from './ui/Button';

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

export function ClientSetup() {
  const [copied, setCopied] = useState('');
  const host = window.location.hostname;
  const proxyPort = String(PROXY_PORT);
  const proxyAddr = proxyAddress();

  const copyTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const copy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    toast.success(`Copied ${label}`);
    if (copyTimer.current) clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(''), 2000);
  };
  useEffect(() => () => { if (copyTimer.current) clearTimeout(copyTimer.current); }, []);

  const pacContent = `function FindProxyForURL(url, host) {
  // Direct access for local network
  if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
  if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";
  if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";
  if (host === "localhost" || host === "127.0.0.1") return "DIRECT";
  // Use proxy for everything else
  return "PROXY ${proxyAddr}; DIRECT";
}`;

  const downloadPAC = () => {
    const blob = new Blob([pacContent], { type: 'application/x-ns-proxy-autoconfig' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'proxy.pac'; a.click();
    URL.revokeObjectURL(url);
    toast.success('PAC file downloaded');
  };

  const tabs = [
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
    },
    {
      id: 'linux', icon: Terminal, label: 'Linux',
      steps: [
        'Add to ~/.bashrc or /etc/environment:',
      ],
      cmd: `export http_proxy=http://${proxyAddr}\nexport https_proxy=http://${proxyAddr}\nexport no_proxy=localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`,
    },
    {
      id: 'ios', icon: Smartphone, label: 'iOS',
      steps: [
        'Open Settings → Wi-Fi → tap your network (i)',
        'Scroll to HTTP Proxy → Configure Proxy → Manual',
        `Server: ${host}`,
        `Port: ${proxyPort}`,
        'Authentication: Off',
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
    },
  ];

  const [activeTab, setActiveTab] = useState('windows');
  const active = tabs.find(t => t.id === activeTab)!;

  return (
    <div className="rounded-panel border border-line bg-surface p-4 text-ink">
      <div className="pb-2">
        <h3 className="text-sm font-semibold leading-none tracking-tight text-ink flex items-center gap-2">
          <QrCode aria-hidden="true" className="w-4 h-4 text-accent" />
          Connect Your Devices
        </h3>
      </div>
      <div className="pt-2">
        {/* Proxy address */}
        <div className="flex items-center gap-2 mb-3 px-3 py-2 bg-accent-subtle border border-accent-line rounded-control">
          <span className="text-xs text-ink-muted">Proxy:</span>
          <code className="text-sm font-bold font-mono text-accent">{proxyAddr}</code>
          <CopyBtn text={proxyAddr} label="proxy" copied={copied} onCopy={copy} />
        </div>

        {/* PAC file download */}
        <div className="flex flex-wrap gap-2 mb-4">
          <Button size="sm" icon={<Download />} onClick={downloadPAC}>
            Download PAC File
          </Button>
          <Button size="sm" icon={<Copy />} onClick={() => copy(pacContent, 'pac')}>
            Copy PAC
          </Button>
        </div>

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

          {/* Command */}
          {active.cmd && (
            <div className="relative">
              <pre className="bg-surface-muted border border-line rounded-control p-3 pr-9 text-xs font-mono text-ink overflow-x-auto whitespace-pre-wrap break-all">
                {active.cmd}
              </pre>
              <button
                type="button"
                onClick={() => copy(active.cmd!, 'cmd')}
                aria-label="Copy command"
                className="absolute top-2 right-2 p-1 rounded-control border border-line bg-surface text-ink-muted hover:bg-surface-muted hover:text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
              >
                {copied === 'cmd' ? <Check aria-hidden="true" className="w-3.5 h-3.5 text-success" /> : <Copy aria-hidden="true" className="w-3.5 h-3.5" />}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
