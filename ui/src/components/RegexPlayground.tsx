import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { FlaskConical, Play, AlertTriangle, Check } from 'lucide-react';
import toast from 'react-hot-toast';
import { api } from '../lib/api';

interface TestResult {
  regex: string;
  hours: number;
  scanned: number;
  matched: number;
  examples: string[];
  would_block: boolean;
}

export function RegexPlayground() {
  const [regex, setRegex] = useState('');
  const [hours, setHours] = useState(24);
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<TestResult | null>(null);

  const handleTest = async () => {
    if (!regex.trim()) return;
    setTesting(true);
    setResult(null);
    try {
      const res = await api.post('waf/test-rule', { regex: regex.trim(), hours });
      setResult(res.data.data);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Test failed';
      toast.error(msg);
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card className="bg-card/50">
      <CardHeader className="p-3 pb-0">
        <CardTitle className="text-sm flex items-center gap-1.5">
          <FlaskConical className="w-3.5 h-3.5 text-purple-500" />
          Regex Playground
        </CardTitle>
      </CardHeader>
      <CardContent className="p-3 pt-2">
        <p className="text-[10px] text-muted-foreground mb-2">
          Test a regex against real proxy traffic before deploying as a WAF rule.
        </p>

        <div className="flex gap-2 mb-2">
          <input
            type="text"
            value={regex}
            onChange={(e) => setRegex(e.target.value)}
            placeholder="e.g. (?i)\.torrent$"
            className="flex-1 bg-background border border-border rounded-md px-2 py-1.5 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-primary"
            onKeyDown={(e) => e.key === 'Enter' && handleTest()}
          />
          <select
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            className="bg-background border border-border rounded-md px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value={1}>1h</option>
            <option value={6}>6h</option>
            <option value={24}>24h</option>
            <option value={72}>72h</option>
            <option value={168}>7d</option>
          </select>
          <button
            type="button"
            onClick={handleTest}
            disabled={testing || !regex.trim()}
            className="flex items-center gap-1 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-xs font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
          >
            <Play className="w-3 h-3" />
            {testing ? 'Testing...' : 'Test'}
          </button>
        </div>

        {result && (
          <div className="space-y-2">
            {/* Summary */}
            <div className={`flex items-center gap-2 p-2 rounded-lg text-xs ${
              result.would_block ? 'bg-destructive/10 border border-destructive/20' : 'bg-emerald-500/10 border border-emerald-500/20'
            }`}>
              {result.would_block
                ? <AlertTriangle className="w-3.5 h-3.5 text-destructive shrink-0" />
                : <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
              }
              <span>
                Scanned <strong>{result.scanned.toLocaleString()}</strong> URLs,{' '}
                <strong className={result.would_block ? 'text-destructive' : 'text-emerald-500'}>
                  {result.matched}
                </strong> matched
                {result.would_block ? ' — this rule WOULD block traffic!' : ' — safe to deploy.'}
              </span>
            </div>

            {/* Examples */}
            {result.examples.length > 0 && (
              <div className="max-h-[120px] overflow-y-auto space-y-0.5">
                {result.examples.slice(0, 10).map((url, i) => (
                  <div key={i} className="text-[10px] font-mono text-muted-foreground truncate px-1" title={url}>
                    {url}
                  </div>
                ))}
                {result.matched > 10 && (
                  <div className="text-[10px] text-muted-foreground px-1">
                    ... and {result.matched - 10} more
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
