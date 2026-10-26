import { useState } from 'react';
import { Shield, Baby, Server, Lock, Monitor, Tv, Wifi, Smartphone, ChevronRight, ChevronLeft, Zap, Check } from 'lucide-react';
import toast from 'react-hot-toast';
import { api } from '../lib/api';
import { cn } from '../lib/utils';
import { useModal } from '../hooks/useModal';
import { ClientSetup } from './ClientSetup';
import { Button } from './ui/Button';

interface Props {
  onComplete: () => void;
}

type Environment = 'homelab' | 'family' | 'smb' | 'advanced';
type StrictLevel = 'relaxed' | 'balanced' | 'strict';

const ENV_OPTIONS: { id: Environment; icon: typeof Shield; label: string; desc: string }[] = [
  { id: 'homelab', icon: Monitor, label: 'Homelab', desc: 'Personal servers, NAS, dev environment' },
  { id: 'family', icon: Baby, label: 'Family', desc: 'Home network with kids, safe browsing' },
  { id: 'smb', icon: Server, label: 'Small Business', desc: 'Office network, compliance needs' },
  { id: 'advanced', icon: Lock, label: 'Advanced', desc: 'I know what I\'m doing, skip wizard' },
];

const DEVICE_OPTIONS: { id: string; icon: typeof Monitor; label: string }[] = [
  { id: 'pcs', icon: Monitor, label: 'PCs / Laptops' },
  { id: 'phones', icon: Smartphone, label: 'Phones / Tablets' },
  { id: 'smart_tv', icon: Tv, label: 'Smart TVs' },
  { id: 'iot', icon: Wifi, label: 'IoT Devices' },
  { id: 'servers', icon: Server, label: 'Servers' },
];

const STRICT_OPTIONS: { id: StrictLevel; label: string; desc: string }[] = [
  { id: 'relaxed', label: 'Relaxed', desc: 'Minimal blocking, just the essentials' },
  { id: 'balanced', label: 'Balanced', desc: 'Good protection without breaking things' },
  { id: 'strict', label: 'Strict', desc: 'Maximum security, may need whitelist tuning' },
];

function mapToPreset(env: Environment, devices: string[], strict: StrictLevel): Record<string, string> {
  const base: Record<string, string> = {
    waf_h_entropy: 'true',
    waf_h_beaconing: 'true',
    waf_h_pii: 'false',
    waf_h_sharding: 'false',
    waf_h_ghosting: 'false',
    ssl_bump_enabled: 'false',
    enable_safesearch: 'false',
    enable_youtube_restricted: 'false',
    enable_content_filtering: 'false',
    enable_bandwidth_limits: 'false',
    enable_time_restrictions: 'false',
    enable_proxy_auth: 'false',
    aggressive_caching_enabled: 'false',
  };

  // Environment overrides
  if (env === 'family') {
    base.enable_safesearch = 'true';
    base.enable_youtube_restricted = 'true';
    base.enable_content_filtering = 'true';
    base.blocked_file_types = 'exe,bat,cmd,dll,msi,scr,ps1,vbs';
  } else if (env === 'smb') {
    base.enable_content_filtering = 'true';
    base.blocked_file_types = 'exe,bat,cmd,dll,msi,scr,ps1,vbs';
    base.waf_h_pii = 'true';
    base.waf_h_sharding = 'true';
    base.waf_h_ghosting = 'true';
  }

  // Device overrides
  if (devices.includes('smart_tv') || devices.includes('iot')) {
    base.waf_h_beaconing = 'true';
    base.waf_h_sharding = 'true';
  }
  if (devices.includes('phones')) {
    base.enable_bandwidth_limits = 'true';
    base.bandwidth_limit_mbps = '50';
    base.bandwidth_limit_per_user_kbps = '2000';
  }

  // Strictness overrides. The WAF's block threshold is WAF_BLOCK_THRESHOLD
  // in .env, read once at WAF start: the wizard cannot set it, so strictness
  // is the set of heuristics and filters it turns on. Direct-IP blocking is
  // always on in the proxy, and offline mode serves stale pages, so neither
  // is a strictness choice (both used to be written here and changed
  // nothing, or the wrong thing).
  if (strict === 'balanced') {
    base.waf_h_ghosting = 'true';
    base.aggressive_caching_enabled = 'true';
  } else if (strict === 'strict') {
    base.waf_h_pii = 'true';
    base.waf_h_sharding = 'true';
    base.waf_h_ghosting = 'true';
    base.enable_content_filtering = 'true';
    base.blocked_file_types = 'exe,bat,cmd,dll,msi,scr,ps1,vbs,sh,py,rb,zip,7z,rar,tar,iso';
    base.aggressive_caching_enabled = 'true';
  }

  return base;
}

export function SetupWizard({ onComplete }: Props) {
  const [step, setStep] = useState(0);
  const [env, setEnv] = useState<Environment | null>(null);
  const [devices, setDevices] = useState<string[]>([]);
  const [strict, setStrict] = useState<StrictLevel>('balanced');
  const [saving, setSaving] = useState(false);
  // First-run gate: trap focus inside the wizard, but no Escape-to-dismiss.
  const modalRef = useModal<HTMLDivElement>(true);

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
      // Saving only writes the toggle files; they take effect when startup.sh
      // regenerates squid.conf, which happens on a proxy reload. Without this the
      // wizard's "Setup complete" was misleading: nothing was actually applied.
      // Fire-and-forget (mirrors Settings.tsx) so we don't block the wizard on
      // the proxy restart; the toast reports progress in the background.
      toast.promise(
        api.post('maintenance/reload-config', {}, {
          headers: { 'Idempotency-Key': `wizard-reload-${Date.now()}` },
        }),
        {
          loading: 'Applying your configuration to the proxy…',
          success: 'Setup complete: your proxy is live with these settings! 🚀',
          error: 'Saved, but auto-apply failed. Use Settings → Admin and backup → Reload Config.',
        }
      );
      // Advance to the final "connect your devices" step instead of closing, so a
      // first-run user is shown how to actually route traffic through the proxy.
      setStep(3);
    } catch {
      toast.error('Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const canNext = step === 0 ? env !== null : step === 1 ? true : true;

  return (
    <div
      ref={modalRef}
      className="fixed inset-0 z-100 bg-ground text-ink flex items-center justify-center p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="setup-wizard-title"
    >
      <div className="w-full max-w-2xl rounded-panel border border-line bg-surface p-6">
        {/* Logo + title */}
        <div className="text-center mb-6">
          <div className="flex justify-center mb-3">
            <div className="w-12 h-12 rounded-panel border border-line bg-surface-muted flex items-center justify-center">
              <img src="/logo.svg" alt="" className="w-7 h-7" />
            </div>
          </div>
          <h1 id="setup-wizard-title" className="text-xl font-semibold tracking-tight text-ink">
            Welcome to Secure Proxy Manager
          </h1>
          <p className="text-sm text-ink-muted mt-1">Let's configure your proxy in 30 seconds</p>
        </div>

        {/* Progress */}
        <div className="flex items-center justify-center gap-2 mb-6" aria-hidden="true">
          {[0, 1, 2, 3].map(i => (
            <div
              key={i}
              className={cn(
                'h-1.5 rounded-full transition-all',
                i === step ? 'w-10 bg-accent-solid' : i < step ? 'w-6 bg-accent-line' : 'w-6 bg-line',
              )}
            />
          ))}
        </div>

        {/* Step content */}
        <div className="min-h-[280px]">
          {step === 0 && (
            <div>
              <h2 className="text-base font-semibold text-ink mb-1">What's your setup?</h2>
              <p className="text-xs text-ink-muted mb-4">This helps us choose the right defaults</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {ENV_OPTIONS.map(opt => {
                  const Icon = opt.icon;
                  const selected = env === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      aria-pressed={selected}
                      onClick={() => setEnv(opt.id)}
                      className={cn(
                        'flex items-start gap-3 p-4 border rounded-control text-left transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
                        selected
                          ? 'border-accent-line bg-accent-subtle ring-1 ring-accent'
                          : 'border-line bg-surface hover:bg-surface-muted',
                      )}
                    >
                      <Icon aria-hidden="true" className={cn('w-5 h-5 mt-0.5 shrink-0', selected ? 'text-accent' : 'text-ink-muted')} />
                      <div>
                        <p className={cn('text-sm font-semibold', selected ? 'text-accent' : 'text-ink')}>{opt.label}</p>
                        <p className="text-xs text-ink-muted mt-0.5">{opt.desc}</p>
                      </div>
                      {selected && <Check aria-hidden="true" className="w-4 h-4 text-accent ml-auto shrink-0 mt-0.5" />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {step === 1 && (
            <div>
              <h2 className="text-base font-semibold text-ink mb-1">What devices use this proxy?</h2>
              <p className="text-xs text-ink-muted mb-4">Select all that apply. This helps tune the blocking rules.</p>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {DEVICE_OPTIONS.map(opt => {
                  const Icon = opt.icon;
                  const selected = devices.includes(opt.id);
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      aria-pressed={selected}
                      onClick={() => toggleDevice(opt.id)}
                      className={cn(
                        'flex flex-col items-center gap-2 p-4 border rounded-control transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
                        selected
                          ? 'border-accent-line bg-accent-subtle ring-1 ring-accent'
                          : 'border-line bg-surface hover:bg-surface-muted',
                      )}
                    >
                      <Icon aria-hidden="true" className={cn('w-5 h-5', selected ? 'text-accent' : 'text-ink-muted')} />
                      <span className={cn('text-xs font-medium', selected ? 'text-accent' : 'text-ink-secondary')}>{opt.label}</span>
                    </button>
                  );
                })}
              </div>
              <p className="text-xs text-ink-muted mt-3 text-center">Skip if unsure. You can always change this later in Settings.</p>
            </div>
          )}

          {step === 2 && (
            <div>
              <h2 className="text-base font-semibold text-ink mb-1">How strict?</h2>
              <p className="text-xs text-ink-muted mb-4">You can fine-tune individual settings anytime</p>
              <div className="space-y-2">
                {STRICT_OPTIONS.map(opt => {
                  const selected = strict === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      aria-pressed={selected}
                      onClick={() => setStrict(opt.id)}
                      className={cn(
                        'w-full flex items-center justify-between p-4 border rounded-control text-left transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
                        selected
                          ? 'border-accent-line bg-accent-subtle ring-1 ring-accent'
                          : 'border-line bg-surface hover:bg-surface-muted',
                      )}
                    >
                      <div>
                        <p className={cn('text-sm font-semibold', selected ? 'text-accent' : 'text-ink')}>{opt.label}</p>
                        <p className="text-xs text-ink-muted">{opt.desc}</p>
                      </div>
                      {selected && <Check aria-hidden="true" className="w-4 h-4 text-accent shrink-0" />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {step === 3 && (
            <div>
              <h2 className="text-base font-semibold text-ink mb-1">You're set: connect your devices</h2>
              <p className="text-xs text-ink-muted mb-4">Point a device at the proxy to start filtering its traffic.</p>
              <div className="max-h-[50vh] overflow-y-auto -mx-1 px-1">
                <ClientSetup />
              </div>
            </div>
          )}
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between mt-6">
          <Button
            variant="ghost"
            icon={<ChevronLeft />}
            onClick={() => setStep(s => s - 1)}
            disabled={step === 0 || step === 3}
            className={step === 0 || step === 3 ? 'invisible' : ''}
          >
            Back
          </Button>

          {step === 3 ? (
            <Button variant="primary" icon={<Check />} onClick={onComplete}>
              Done
            </Button>
          ) : env === 'advanced' && step === 0 ? (
            <Button variant="secondary" onClick={handleFinish}>
              Skip Wizard <ChevronRight aria-hidden="true" className="w-4 h-4" />
            </Button>
          ) : step < 2 ? (
            <Button variant="primary" onClick={() => setStep(s => s + 1)} disabled={!canNext}>
              Next <ChevronRight aria-hidden="true" className="w-4 h-4" />
            </Button>
          ) : (
            <Button variant="primary" icon={<Zap />} onClick={handleFinish} disabled={saving}>
              {saving ? 'Applying...' : 'Apply & Start'}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
