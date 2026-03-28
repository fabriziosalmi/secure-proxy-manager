import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../ui/card';
import { Database, Download, Trash2, RotateCcw, Wrench } from 'lucide-react';
import toast from 'react-hot-toast';
import { api } from '../../lib/api';

export function Maintenance() {
  const action = async (label: string, fn: () => Promise<unknown>) => {
    const id = toast.loading(`${label}...`);
    try {
      await fn();
      toast.success(`${label} complete`, { id });
    } catch {
      toast.error(`${label} failed`, { id });
    }
  };

  const handleBackup = () => action('Backup', async () => {
    const res = await api.get('database/export', { responseType: 'blob' });
    const url = window.URL.createObjectURL(new Blob([res.data]));
    const a = document.createElement('a'); a.href = url;
    a.download = `proxy-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click(); window.URL.revokeObjectURL(url);
  });

  const handleClearCache = () => action('Clear cache', () => api.post('maintenance/clear-cache'));
  const handleOptimize = () => action('Optimize DB', () => api.post('database/optimize'));
  const handleResetCounters = () => action('Reset counters', () => api.post('counters/reset'));
  const handleReloadConfig = () => action('Reload config', () => api.post('maintenance/reload-config'));
  const handleReloadDns = () => action('Reload DNS', () => api.post('maintenance/reload-dns'));

  const Btn = ({ icon: Icon, label, sub, onClick, destructive }: {
    icon: typeof Download; label: string; sub: string; onClick: () => void; destructive?: boolean;
  }) => (
    <button
      type="button"
      onClick={onClick}
      className={`flex items-center gap-3 p-3 border border-border rounded-lg bg-background/50 transition-colors text-left w-full ${
        destructive ? 'hover:bg-destructive/10 group' : 'hover:bg-secondary/50'
      }`}
    >
      <Icon className={`w-4 h-4 shrink-0 ${destructive ? 'text-destructive group-hover:text-red-400' : 'text-primary'}`} />
      <div>
        <span className={`text-xs font-medium ${destructive ? 'text-destructive group-hover:text-red-400' : ''}`}>{label}</span>
        <p className="text-[10px] text-muted-foreground">{sub}</p>
      </div>
    </button>
  );

  return (
    <Card className="bg-card/50">
      <CardHeader className="p-4 pb-2">
        <div className="flex items-center gap-2">
          <Database className="w-4 h-4 text-muted-foreground" />
          <CardTitle className="text-sm">Maintenance</CardTitle>
        </div>
        <CardDescription className="text-xs">System backup, cache, and database management</CardDescription>
      </CardHeader>
      <CardContent className="p-4 pt-0">
        <div className="grid grid-cols-2 gap-2">
          <Btn icon={Download} label="Backup Config" sub="Download settings JSON" onClick={handleBackup} />
          <Btn icon={Wrench} label="Optimize DB" sub="Vacuum + reindex" onClick={handleOptimize} />
          <Btn icon={RotateCcw} label="Reload Config" sub="Apply Squid changes" onClick={handleReloadConfig} />
          <Btn icon={RotateCcw} label="Reload DNS" sub="Apply domain blocklist" onClick={handleReloadDns} />
          <Btn icon={RotateCcw} label="Reset Counters" sub="Zero all stats" onClick={handleResetCounters} destructive />
          <Btn icon={Trash2} label="Clear Cache" sub="Free proxy memory" onClick={handleClearCache} destructive />
        </div>
      </CardContent>
    </Card>
  );
}
