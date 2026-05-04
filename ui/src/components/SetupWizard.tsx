import { useState } from 'react';
import { Shield, Baby, Server, Lock, Monitor, Tv, Wifi, Smartphone, ChevronRight, ChevronLeft, Zap, Check } from 'lucide-react';
import toast from 'react-hot-toast';
import { api } from '../lib/api';

interface Props {
  onComplete: () => void;
}

type Environment = 'homelab' | 'family' | 'smb' | 'advanced';
type StrictLevel = 'relaxed' | 'balanced' | 'strict';

const ENV_OPTIONS: { id: Environment; icon: typeof Shield; color: string; label: string; desc: string }[] = [
  { id: 'homelab', icon: Monitor, color: 'text-cyan-400', label: 'Homelab', desc: 'Personal servers, NAS, dev environment' },
  { id: 'family', icon: Baby, color: 'text-blue-400', label: 'Family', desc: 'Home network with kids, safe browsing' },
  { id: 'smb', icon: Server, color: 'text-yellow-400', label: 'Small Business', desc: 'Office network, compliance needs' },
  { id: 'advanced', icon: Lock, color: 'text-red-400', label: 'Advanced', desc: 'I know what I\'m doing, skip wizard' },
];

const DEVICE_OPTIONS: { id: string; icon: typeof Monitor; label: string }[] = [
  { id: 'pcs', icon: Monitor, label: 'PCs / Laptops' },
  { id: 'phones', icon: Smartphone, label: 'Phones / Tablets' },
  { id: 'smart_tv', icon: Tv, label: 'Smart TVs' },
  { id: 'iot', icon: Wifi, label: 'IoT Devices' },
  { id: 'servers', icon: Server, label: 'Servers' },
];

const STRICT_OPTIONS: { id: StrictLevel; color: string; label: string; desc: string }[] = [
  { id: 'relaxed', color: 'text-emerald-400', label: 'Relaxed', desc: 'Minimal blocking, just the essentials' },
  { id: 'balanced', color: 'text-yellow-400', label: 'Balanced', desc: 'Good protection without breaking things' },
  { id: 'strict', color: 'text-red-400', label: 'Strict', desc: 'Maximum security, may need whitelist tuning' },
];

function mapToPreset(env: Environment, devices: string[], strict: StrictLevel): Record<string, string> {
  const base: Record<string, string> = {
    heuristic_entropy: 'true',
    heuristic_beaconing: 'true',
    heuristic_pii_leak: 'false',
    heuristic_dest_sharding: 'false',
    heuristic_protocol_ghosting: 'false',
    heuristic_header_morphing: 'false',
    ssl_bump_enabled: 'false',
    block_direct_ip: 'false',
    enable_safesearch: 'false',
    enable_youtube_restricted: 'false',
    enable_content_filtering: 'false',
    enable_bandwidth_limits: 'false',
    enable_time_restrictions: 'false',
    enable_proxy_auth: 'false',
    aggressive_caching: 'false',
    enable_offline_mode: 'false',
    waf_block_threshold: '10',
  };

  // Environment overrides
  if (env === 'family') {
    base.enable_safesearch = 'true';
    base.enable_youtube_restricted = 'true';
    base.enable_content_filtering = 'true';
    base.blocked_file_types = 'exe,bat,cmd,dll,msi,scr,ps1,vbs';
    base.block_direct_ip = 'true';
  } else if (env === 'smb') {
    base.block_direct_ip = 'true';
    base.enable_content_filtering = 'true';
    base.blocked_file_types = 'exe,bat,cmd,dll,msi,scr,ps1,vbs,js';
    base.heuristic_pii_leak = 'true';
    base.heuristic_dest_sharding = 'true';
    base.heuristic_protocol_ghosting = 'true';
  }

  // Device overrides
  if (devices.includes('smart_tv') || devices.includes('iot')) {
    base.block_direct_ip = 'true';
    base.heuristic_beaconing = 'true';
    base.heuristic_dest_sharding = 'true';
  }
  if (devices.includes('phones')) {
    base.enable_bandwidth_limits = 'true';
    base.bandwidth_limit_mbps = '50';
    base.bandwidth_limit_per_user_kbps = '2000';
  }

  // Strictness overrides
  if (strict === 'relaxed') {
    base.waf_block_threshold = '15';
  } else if (strict === 'balanced') {
    base.waf_block_threshold = '8';
    base.heuristic_protocol_ghosting = 'true';
    base.aggressive_caching = 'true';
  } else if (strict === 'strict') {
    base.waf_block_threshold = '5';
    base.heuristic_pii_leak = 'true';
    base.heuristic_dest_sharding = 'true';
    base.heuristic_protocol_ghosting = 'true';
    base.heuristic_header_morphing = 'true';
    base.enable_content_filtering = 'true';
    base.blocked_file_types = 'exe,bat,cmd,dll,msi,scr,ps1,vbs,js,sh,py,rb,zip,7z,rar,tar,iso';
    base.block_direct_ip = 'true';
    base.aggressive_caching = 'true';
    base.enable_offline_mode = 'true';
  }

  return base;
}

export function SetupWizard({ onComplete }: Props) {
  const [step, setStep] = useState(0);
  const [env, setEnv] = useState<Environment | null>(null);
  const [devices, setDevices] = useState<string[]>([]);
  const [strict, setStrict] = useState<StrictLevel>('balanced');
  const [saving, setSaving] = useState(false);

  const toggleDevice = (id: string) => {
    setDevices(prev => prev.includes(id) ? prev.filter(d => d !== id) : [...prev, id]);
  };

  const handleFinish = async () => {
    if (!env) return;

    // Advanced = skip wizard, just mark complete
    if (env === 'advanced') {
      try {
        await api.post('settings', { wizard_completed: 'true' });
      } catch { /* ignore */ }
      onComplete();
      return;
    }

    setSaving(true);
    try {
      const settings = mapToPreset(env, devices, strict);
      settings.wizard_completed = 'true';
      await api.post('settings', settings);
      toast.success('Setup complete! Your proxy is configured.', { duration: 5000, icon: '🚀' });
      onComplete();
    } catch {
      toast.error('Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const canNext = step === 0 ? env !== null : step === 1 ? true : true;

  return (
    <div
      className="fixed inset-0 z-[100] bg-background flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="setup-wizard-title"
    >
      <div className="w-full max-w-2xl">
        {/* Logo + title */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <img src="/logo.svg" alt="" className="w-12 h-12" />
          </div>
          <h1 id="setup-wizard-title" className="text-2xl font-bold tracking-tight">Welcome to Secure Proxy Manager</h1>
          <p className="text-sm text-muted-foreground mt-1">Let's configure your proxy in 30 seconds</p>
        </div>

        {/* Progress */}
        <div className="flex items-center justify-center gap-2 mb-8">
          {[0, 1, 2].map(i => (
            <div key={i} className={`h-1.5 rounded-full transition-all ${
              i === step ? 'w-10 bg-primary' : i < step ? 'w-6 bg-primary/50' : 'w-6 bg-secondary'
            }`} />
          ))}
        </div>

        {/* Step content */}
        <div className="min-h-[280px]">
          {step === 0 && (
            <div>
              <h2 className="text-lg font-semibold mb-1">What's your setup?</h2>
              <p className="text-xs text-muted-foreground mb-4">This helps us choose the right defaults</p>
              <div className="grid grid-cols-2 gap-3">
                {ENV_OPTIONS.map(opt => {
                  const Icon = opt.icon;
                  const selected = env === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => setEnv(opt.id)}
                      className={`flex items-start gap-3 p-4 border rounded-lg text-left transition-all ${
                        selected ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border hover:border-border/80 hover:bg-secondary/30'
                      }`}
                    >
                      <Icon className={`w-5 h-5 mt-0.5 shrink-0 ${selected ? opt.color : 'text-muted-foreground'}`} />
                      <div>
                        <p className={`text-sm font-medium ${selected ? opt.color : ''}`}>{opt.label}</p>
                        <p className="text-[11px] text-muted-foreground mt-0.5">{opt.desc}</p>
                      </div>
                      {selected && <Check className="w-4 h-4 text-primary ml-auto shrink-0 mt-0.5" />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {step === 1 && (
            <div>
              <h2 className="text-lg font-semibold mb-1">What devices use this proxy?</h2>
              <p className="text-xs text-muted-foreground mb-4">Select all that apply — helps us tune blocking rules</p>
              <div className="grid grid-cols-3 gap-2">
                {DEVICE_OPTIONS.map(opt => {
                  const Icon = opt.icon;
                  const selected = devices.includes(opt.id);
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => toggleDevice(opt.id)}
                      className={`flex flex-col items-center gap-2 p-4 border rounded-lg transition-all ${
                        selected ? 'border-primary bg-primary/5' : 'border-border hover:border-border/80 hover:bg-secondary/30'
                      }`}
                    >
                      <Icon className={`w-5 h-5 ${selected ? 'text-primary' : 'text-muted-foreground'}`} />
                      <span className={`text-xs font-medium ${selected ? 'text-primary' : 'text-muted-foreground'}`}>{opt.label}</span>
                    </button>
                  );
                })}
              </div>
              <p className="text-[10px] text-muted-foreground mt-3 text-center">Skip if unsure — you can always change this later in Settings</p>
            </div>
          )}

          {step === 2 && (
            <div>
              <h2 className="text-lg font-semibold mb-1">How strict?</h2>
              <p className="text-xs text-muted-foreground mb-4">You can fine-tune individual settings anytime</p>
              <div className="space-y-2">
                {STRICT_OPTIONS.map(opt => {
                  const selected = strict === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => setStrict(opt.id)}
                      className={`w-full flex items-center justify-between p-4 border rounded-lg text-left transition-all ${
                        selected ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border hover:border-border/80 hover:bg-secondary/30'
                      }`}
                    >
                      <div>
                        <p className={`text-sm font-bold ${selected ? opt.color : ''}`}>{opt.label}</p>
                        <p className="text-[11px] text-muted-foreground">{opt.desc}</p>
                      </div>
                      {selected && <Check className="w-4 h-4 text-primary shrink-0" />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between mt-6">
          <button
            type="button"
            onClick={() => setStep(s => s - 1)}
            disabled={step === 0}
            className="flex items-center gap-1 px-4 py-2 text-sm text-muted-foreground hover:text-foreground disabled:opacity-0 transition-all"
          >
            <ChevronLeft className="w-4 h-4" /> Back
          </button>

          {env === 'advanced' && step === 0 ? (
            <button
              type="button"
              onClick={handleFinish}
              className="flex items-center gap-2 px-6 py-2 bg-secondary text-foreground rounded-lg text-sm font-medium hover:bg-secondary/80 transition-colors"
            >
              Skip Wizard <ChevronRight className="w-4 h-4" />
            </button>
          ) : step < 2 ? (
            <button
              type="button"
              onClick={() => setStep(s => s + 1)}
              disabled={!canNext}
              className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          ) : (
            <button
              type="button"
              onClick={handleFinish}
              disabled={saving}
              className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              <Zap className="w-4 h-4" />
              {saving ? 'Applying...' : 'Apply & Start'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
