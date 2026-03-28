import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Monitor, Smartphone, Apple, Terminal, Copy, Check, Download, QrCode } from 'lucide-react';
import toast from 'react-hot-toast';

export function ClientSetup() {
  const [copied, setCopied] = useState('');
  const host = window.location.hostname;
  const proxyPort = '3128';
  const proxyAddr = `${host}:${proxyPort}`;

  const copy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    toast.success(`Copied ${label}`);
    setTimeout(() => setCopied(''), 2000);
  };

  const CopyBtn = ({ text, label }: { text: string; label: string }) => (
    <button type="button" onClick={() => copy(text, label)}
      className="p-1 rounded hover:bg-secondary/50 transition-colors shrink-0">
      {copied === label ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-muted-foreground" />}
    </button>
  );

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
    <Card className="bg-card/50">
      <CardHeader className="p-4 pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <QrCode className="w-4 h-4 text-primary" />
          Connect Your Devices
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-2">
        {/* Proxy address */}
        <div className="flex items-center gap-2 mb-3 p-2 bg-primary/5 border border-primary/20 rounded-lg">
          <span className="text-xs text-muted-foreground">Proxy:</span>
          <code className="text-sm font-bold font-mono text-primary">{proxyAddr}</code>
          <CopyBtn text={proxyAddr} label="proxy" />
        </div>

        {/* PAC file download */}
        <div className="flex gap-2 mb-4">
          <button type="button" onClick={downloadPAC}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-secondary rounded-md hover:bg-secondary/80 transition-colors">
            <Download className="w-3.5 h-3.5" /> Download PAC File
          </button>
          <button type="button" onClick={() => copy(pacContent, 'pac')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-secondary rounded-md hover:bg-secondary/80 transition-colors">
            <Copy className="w-3.5 h-3.5" /> Copy PAC
          </button>
        </div>

        {/* OS tabs */}
        <div className="flex gap-1 mb-3 border-b border-border pb-2">
          {tabs.map(t => {
            const Icon = t.icon;
            return (
              <button key={t.id} type="button" onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-1 px-2 py-1 text-[11px] rounded-md transition-colors ${
                  activeTab === t.id ? 'bg-primary/10 text-primary font-medium' : 'text-muted-foreground hover:text-foreground'
                }`}>
                <Icon className="w-3 h-3" /> {t.label}
              </button>
            );
          })}
        </div>

        {/* Steps */}
        <ol className="space-y-1 mb-3">
          {active.steps.map((step, i) => (
            <li key={i} className="flex gap-2 text-xs">
              <span className="text-muted-foreground font-bold shrink-0">{i + 1}.</span>
              <span>{step}</span>
            </li>
          ))}
        </ol>

        {/* Command */}
        {active.cmd && (
          <div className="relative">
            <pre className="bg-[#0a0a0a] border border-border rounded-lg p-3 text-[11px] font-mono text-emerald-400 overflow-x-auto whitespace-pre-wrap">
              {active.cmd}
            </pre>
            <button type="button" onClick={() => copy(active.cmd!, 'cmd')}
              className="absolute top-2 right-2 p-1 rounded bg-secondary/80 hover:bg-secondary">
              {copied === 'cmd' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-muted-foreground" />}
            </button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
