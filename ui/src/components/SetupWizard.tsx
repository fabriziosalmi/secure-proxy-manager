import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Shield, Baby, Server, Lock, Monitor, ChevronRight, ChevronLeft, Zap, Check } from 'lucide-react';
import toast from 'react-hot-toast';
import { api } from '../lib/api';
import { applyToProxy, describeApply, type ApplyOutcome } from '../lib/reload';
import { cn } from '../lib/utils';
import { useModal } from '../hooks/useModal';
import { ClientSetup } from './ClientSetup';
import { Button } from './ui/Button';
import { Notice, type NoticeTone } from './ui/Notice';

interface Props {
  onComplete: () => void;
}

type Environment = 'homelab' | 'family' | 'smb' | 'advanced';
type StrictLevel = 'relaxed' | 'balanced' | 'strict';

const RISKY_EXEC = 'exe,bat,cmd,dll,msi,scr,ps1,vbs';
const RISKY_ALL = 'exe,bat,cmd,dll,msi,scr,ps1,vbs,sh,py,rb,zip,7z,rar,tar,iso';

const ENV_OPTIONS: { id: Environment; icon: typeof Shield; label: string; desc: string }[] = [
  {
    id: 'homelab',
    icon: Monitor,
    label: 'Homelab',
    desc: 'Turns on entropy and beaconing WAF heuristics; leaves SafeSearch, YouTube restricted mode, and file-type blocking off.',
  },
  {
    id: 'family',
    icon: Baby,
    label: 'Family',
    desc: 'Turns on SafeSearch, YouTube restricted mode, entropy and beaconing WAF heuristics, and blocks executable and script downloads (exe, bat, cmd, dll, msi, scr, ps1, vbs).',
  },
  {
    id: 'smb',
    icon: Server,
    label: 'Small Business',
    desc: 'Turns on all five WAF heuristics (entropy, beaconing, PII, sharding, ghosting) and blocks executable and script downloads (exe, bat, cmd, dll, msi, scr, ps1, vbs).',
  },
  {
    id: 'advanced',
    icon: Lock,
    label: 'Advanced',
    desc: 'Skips the wizard and keeps the current settings untouched.',
  },
];

const STRICT_OPTIONS: { id: StrictLevel; label: string; desc: string }[] = [
  {
    id: 'relaxed',
    label: 'Relaxed',
    desc: 'Keeps only the WAF heuristics and filters from the chosen setup, without extra rules.',
  },
  {
    id: 'balanced',
    label: 'Balanced',
    desc: 'Also turns on the protocol ghosting WAF heuristic on top of the chosen setup.',
  },
  {
    id: 'strict',
    label: 'Strict',
    desc: 'Turns on all five WAF heuristics (entropy, beaconing, PII, sharding, ghosting) and blocks executable, script, and archive downloads: exe, bat, cmd, dll, msi, scr, ps1, vbs, zip, 7z, rar, tar, iso, sh, py, rb.',
  },
];

function mapToPreset(env: Environment, strict: StrictLevel): Record<string, string> {
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

  if (env === 'family') {
    base.enable_safesearch = 'true';
    base.enable_youtube_restricted = 'true';
    base.enable_content_filtering = 'true';
    base.blocked_file_types = RISKY_EXEC;
  } else if (env === 'smb') {
    base.enable_content_filtering = 'true';
    base.blocked_file_types = RISKY_EXEC;
    base.waf_h_pii = 'true';
    base.waf_h_sharding = 'true';
    base.waf_h_ghosting = 'true';
  }

  // The WAF's block threshold is WAF_BLOCK_THRESHOLD in .env, read once at WAF
  // start: the wizard cannot set it, so strictness is the set of heuristics and
  // filters it turns on. Direct-IP blocking is always on in the proxy, offline
  // mode serves stale pages, and aggressive_caching_enabled overrides upstream
  // cache headers (profiles.ts and EngineSection advise against turning it on by
  // default), so none of those is enabled here.
  if (strict === 'balanced') {
    base.waf_h_ghosting = 'true';
  } else if (strict === 'strict') {
    base.waf_h_pii = 'true';
    base.waf_h_sharding = 'true';
    base.waf_h_ghosting = 'true';
    base.enable_content_filtering = 'true';
    base.blocked_file_types = RISKY_ALL;
  }

  return base;
}

function formatWizardApply(outcome: ApplyOutcome): { tone: NoticeTone; title: string; text: string } {
  const base = describeApply(outcome, 'Saved');
  if (outcome.kind === 'applied') {
    return {
      tone: 'info',
      title: 'Configuration applied',
      text: base.text,
    };
  }
  const title =
    outcome.kind === 'pending'
      ? 'Saved, waiting for the proxy'
      : outcome.kind === 'refused'
        ? 'Proxy refused the configuration'
        : 'Could not reload the proxy';
  return {
    tone: base.tone === 'warning' ? 'warning' : 'danger',
    title,
    text: `${base.text} Use Settings, Admin and backup, Reload the proxy to retry.`,
  };
}

export function SetupWizard({ onComplete }: Props) {
  const queryClient = useQueryClient();
  const [step, setStep] = useState(0);
  const [env, setEnv] = useState<Environment | null>(null);
  const [strict, setStrict] = useState<StrictLevel>('balanced');
  const [saving, setSaving] = useState(false);
  const [applyOutcome, setApplyOutcome] = useState<ApplyOutcome | null>(null);
  // First-run gate: trap focus inside the wizard, but no Escape-to-dismiss.
  const modalRef = useModal<HTMLDivElement>(true);

  const handleFinish = async () => {
    if (!env) return;

    // Advanced = skip wizard, just mark complete
    if (env === 'advanced') {
      try {
        await api.post('settings', { wizard_completed: 'true' });
        await queryClient.invalidateQueries({ queryKey: ['settings'] });
      } catch { /* ignore */ }
      onComplete();
      return;
    }

    setSaving(true);
    try {
      const settings = mapToPreset(env, strict);
      settings.wizard_completed = 'true';
      await api.post('settings', settings);
      await queryClient.invalidateQueries({ queryKey: ['settings'] });

      const outcome = await applyToProxy();
      setApplyOutcome(outcome);
      setStep(2);
    } catch {
      toast.error('Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const canNext = step === 0 ? env !== null : true;
  const applyNotice = applyOutcome ? formatWizardApply(applyOutcome) : null;

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
          {[0, 1, 2].map(i => (
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
              <p className="text-xs text-ink-muted mb-4">Each option lists the filters and heuristics it turns on</p>
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
              <h2 className="text-base font-semibold text-ink mb-1">How strict?</h2>
              <p className="text-xs text-ink-muted mb-4">You can fine-tune individual settings anytime in Settings</p>
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
                        'w-full flex items-center justify-between gap-3 p-4 border rounded-control text-left transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
                        selected
                          ? 'border-accent-line bg-accent-subtle ring-1 ring-accent'
                          : 'border-line bg-surface hover:bg-surface-muted',
                      )}
                    >
                      <div>
                        <p className={cn('text-sm font-semibold', selected ? 'text-accent' : 'text-ink')}>{opt.label}</p>
                        <p className="text-xs text-ink-muted mt-0.5">{opt.desc}</p>
                      </div>
                      {selected && <Check aria-hidden="true" className="w-4 h-4 text-accent shrink-0" />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-3">
              <div>
                <h2 className="text-base font-semibold text-ink mb-1">Connect your devices</h2>
                <p className="text-xs text-ink-muted">Point a device at the proxy to start filtering its traffic.</p>
              </div>
              {applyNotice && (
                <Notice tone={applyNotice.tone} title={applyNotice.title}>
                  {applyNotice.text}
                </Notice>
              )}
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
            disabled={step === 0 || step === 2}
            className={step === 0 || step === 2 ? 'invisible' : ''}
          >
            Back
          </Button>

          {step === 2 ? (
            <Button variant="primary" icon={<Check />} onClick={onComplete}>
              Done
            </Button>
          ) : env === 'advanced' && step === 0 ? (
            <Button variant="secondary" onClick={handleFinish}>
              Skip Wizard <ChevronRight aria-hidden="true" className="w-4 h-4" />
            </Button>
          ) : step < 1 ? (
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
