import { Shield, Baby, Server, Lock, Code, MonitorOff } from 'lucide-react';
import toast from 'react-hot-toast';

interface PresetConfig {
  id: string;
  name: string;
  icon: typeof Shield;
  color: string;
  bgColor: string;
  desc: string;
  detail: string;
  values: Record<string, string>;
}

const PRESETS: PresetConfig[] = [
  {
    id: 'basic',
    name: 'Basic',
    icon: Shield,
    color: 'text-emerald-400',
    bgColor: 'border-emerald-500/30 hover:border-emerald-500/60 hover:bg-emerald-500/5',
    desc: 'Just works',
    detail: 'Minimal filtering. WAF active with permissive threshold. No HTTPS inspection. Good starting point.',
    values: {
      waf_block_threshold: '15',
      enable_https_filtering: 'false',
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
      heuristic_entropy: 'true',
      heuristic_beaconing: 'false',
      heuristic_pii_leak: 'false',
      heuristic_dest_sharding: 'false',
      heuristic_protocol_ghosting: 'false',
      heuristic_header_morphing: 'false',
    },
  },
  {
    id: 'family',
    name: 'Family',
    icon: Baby,
    color: 'text-blue-400',
    bgColor: 'border-blue-500/30 hover:border-blue-500/60 hover:bg-blue-500/5',
    desc: 'Safe for kids',
    detail: 'SafeSearch enforced, YouTube restricted, dangerous downloads blocked, bandwidth limited.',
    values: {
      waf_block_threshold: '10',
      enable_https_filtering: 'false',
      ssl_bump_enabled: 'false',
      block_direct_ip: 'true',
      enable_safesearch: 'true',
      enable_youtube_restricted: 'true',
      enable_content_filtering: 'true',
      blocked_file_types: 'exe,bat,cmd,dll,msi,scr,ps1,vbs',
      enable_bandwidth_limits: 'true',
      bandwidth_limit_mbps: '10',
      bandwidth_limit_per_user_kbps: '500',
      enable_time_restrictions: 'false',
      enable_proxy_auth: 'false',
      aggressive_caching: 'true',
      enable_offline_mode: 'false',
      heuristic_entropy: 'true',
      heuristic_beaconing: 'true',
      heuristic_pii_leak: 'true',
      heuristic_dest_sharding: 'false',
      heuristic_protocol_ghosting: 'false',
      heuristic_header_morphing: 'false',
    },
  },
  {
    id: 'standard',
    name: 'Standard',
    icon: Server,
    color: 'text-yellow-400',
    bgColor: 'border-yellow-500/30 hover:border-yellow-500/60 hover:bg-yellow-500/5',
    desc: 'Homelab / SMB',
    detail: 'Balanced WAF, direct IP blocked, content filtering, most heuristics active. Recommended.',
    values: {
      waf_block_threshold: '8',
      enable_https_filtering: 'false',
      ssl_bump_enabled: 'false',
      block_direct_ip: 'true',
      enable_safesearch: 'false',
      enable_youtube_restricted: 'false',
      enable_content_filtering: 'true',
      blocked_file_types: 'exe,bat,cmd,dll,msi,scr,ps1,vbs,js',
      enable_bandwidth_limits: 'false',
      enable_time_restrictions: 'false',
      enable_proxy_auth: 'false',
      aggressive_caching: 'false',
      enable_offline_mode: 'false',
      heuristic_entropy: 'true',
      heuristic_beaconing: 'true',
      heuristic_pii_leak: 'true',
      heuristic_dest_sharding: 'true',
      heuristic_protocol_ghosting: 'true',
      heuristic_header_morphing: 'false',
    },
  },
  {
    id: 'paranoid',
    name: 'Paranoid',
    icon: Lock,
    color: 'text-red-400',
    bgColor: 'border-red-500/30 hover:border-red-500/60 hover:bg-red-500/5',
    desc: 'Maximum security',
    detail: 'Strictest WAF, all heuristics, all filters. SSL Bump requires CA cert on clients.',
    values: {
      waf_block_threshold: '5',
      enable_https_filtering: 'true',
      ssl_bump_enabled: 'true',
      block_direct_ip: 'true',
      enable_safesearch: 'true',
      enable_youtube_restricted: 'true',
      enable_content_filtering: 'true',
      blocked_file_types: 'exe,bat,cmd,dll,msi,scr,ps1,vbs,js,sh,py,rb,zip,7z,rar,tar,iso',
      enable_bandwidth_limits: 'true',
      bandwidth_limit_mbps: '50',
      bandwidth_limit_per_user_kbps: '2000',
      enable_time_restrictions: 'false',
      enable_proxy_auth: 'true',
      auth_method: 'basic',
      aggressive_caching: 'true',
      enable_offline_mode: 'true',
      heuristic_entropy: 'true',
      heuristic_beaconing: 'true',
      heuristic_pii_leak: 'true',
      heuristic_dest_sharding: 'true',
      heuristic_protocol_ghosting: 'true',
      heuristic_header_morphing: 'true',
    },
  },
  {
    id: 'devops',
    name: 'DevOps',
    icon: Code,
    color: 'text-purple-400',
    bgColor: 'border-purple-500/30 hover:border-purple-500/60 hover:bg-purple-500/5',
    desc: 'Developer tools',
    detail: 'Permissive for dev workflows. Content filter off (devs download binaries). All heuristics on.',
    values: {
      waf_block_threshold: '10',
      enable_https_filtering: 'false',
      ssl_bump_enabled: 'false',
      block_direct_ip: 'false',
      enable_safesearch: 'false',
      enable_youtube_restricted: 'false',
      enable_content_filtering: 'false',
      enable_bandwidth_limits: 'false',
      enable_time_restrictions: 'false',
      enable_proxy_auth: 'false',
      aggressive_caching: 'true',
      enable_offline_mode: 'false',
      heuristic_entropy: 'true',
      heuristic_beaconing: 'true',
      heuristic_pii_leak: 'true',
      heuristic_dest_sharding: 'true',
      heuristic_protocol_ghosting: 'true',
      heuristic_header_morphing: 'false',
    },
  },
  {
    id: 'kiosk',
    name: 'Kiosk',
    icon: MonitorOff,
    color: 'text-amber-400',
    bgColor: 'border-amber-500/30 hover:border-amber-500/60 hover:bg-amber-500/5',
    desc: 'Whitelist-only',
    detail: 'Block everything except whitelisted domains. For public terminals, libraries, schools.',
    values: {
      waf_block_threshold: '5',
      enable_https_filtering: 'false',
      ssl_bump_enabled: 'false',
      block_direct_ip: 'true',
      enable_safesearch: 'true',
      enable_youtube_restricted: 'true',
      enable_content_filtering: 'true',
      blocked_file_types: 'exe,bat,cmd,dll,msi,scr,ps1,vbs,js,sh,py,rb,zip,7z,rar,tar,iso',
      enable_bandwidth_limits: 'true',
      bandwidth_limit_mbps: '10',
      bandwidth_limit_per_user_kbps: '500',
      enable_time_restrictions: 'true',
      time_restriction_start: '08:00',
      time_restriction_end: '18:00',
      enable_proxy_auth: 'true',
      auth_method: 'basic',
      aggressive_caching: 'true',
      enable_offline_mode: 'true',
      heuristic_entropy: 'true',
      heuristic_beaconing: 'true',
      heuristic_pii_leak: 'true',
      heuristic_dest_sharding: 'true',
      heuristic_protocol_ghosting: 'true',
      heuristic_header_morphing: 'true',
      kiosk_mode: 'true',
    },
  },
];

interface Props {
  formData: Record<string, string>;
  onApply: (values: Record<string, string>) => void;
}

/** Detect which preset (if any) matches current formData */
function detectPreset(formData: Record<string, string>): string | null {
  for (const preset of PRESETS) {
    const matches = Object.entries(preset.values).every(
      ([key, val]) => formData[key] === val
    );
    if (matches) return preset.id;
  }
  return null;
}

export function Presets({ formData, onApply }: Props) {
  const active = detectPreset(formData);

  const handleApply = (preset: PresetConfig) => {
    onApply(preset.values);
    toast.success(`"${preset.name}" preset applied — click Save Changes to persist`, {
      duration: 4000,
      icon: '⚡',
    });
  };

  return (
    <div className="mb-4">
      <label className="text-xs font-medium text-muted-foreground mb-2 block">Quick Setup Presets</label>
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-2">
        {PRESETS.map((p) => {
          const Icon = p.icon;
          const isActive = active === p.id;
          return (
            <button
              key={p.id}
              type="button"
              onClick={() => handleApply(p)}
              className={`relative flex flex-col items-start p-3 border rounded-lg transition-all text-left ${p.bgColor} ${
                isActive ? 'ring-1 ring-offset-1 ring-offset-background ring-primary' : ''
              }`}
            >
              {isActive && (
                <span className="absolute top-1.5 right-1.5 text-[8px] px-1.5 py-0.5 rounded-full bg-primary/20 text-primary font-medium">
                  Active
                </span>
              )}
              <Icon className={`w-4 h-4 mb-1.5 ${p.color}`} />
              <p className={`text-xs font-bold ${p.color}`}>{p.name}</p>
              <p className="text-[10px] text-muted-foreground">{p.desc}</p>
              <p className="text-[9px] text-muted-foreground/60 mt-1 line-clamp-2">{p.detail}</p>
            </button>
          );
        })}
      </div>
      {active && (
        <p className="text-[10px] text-muted-foreground mt-1.5">
          Current configuration matches <span className="font-medium text-foreground">{PRESETS.find(p => p.id === active)?.name}</span> preset. You can customize individual settings below.
        </p>
      )}
      {!active && Object.keys(formData).length > 0 && (
        <p className="text-[10px] text-muted-foreground mt-1.5">
          Custom configuration — doesn't match any preset.
        </p>
      )}
    </div>
  );
}
