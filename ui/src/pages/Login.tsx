import { useState } from 'react';
import { Shield } from 'lucide-react';
import { api } from '../lib/api';

interface Props {
  onLogin: () => void;
}

export function Login({ onLogin }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await api.post<{ access_token?: string; token?: string }>('auth/login', { username, password });
      const token = res.data.access_token || res.data.token;
      if (!token) throw new Error('No token received');
      localStorage.setItem('auth_token', token);
      onLogin();
    } catch {
      setError('Invalid username or password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-4 ambient-glow">
      <div className="w-full max-w-sm space-y-6 page-enter">
        <div className="text-center space-y-2">
          <div className="flex justify-center">
            <div className="relative w-14 h-14 rounded-2xl bg-primary/10 flex items-center justify-center">
              <Shield className="w-7 h-7 text-primary" />
              <div className="absolute inset-0 rounded-2xl bg-primary/5 animate-glow-pulse" />
            </div>
          </div>
          <h1 className="text-2xl font-extrabold tracking-tight bg-gradient-to-b from-white to-white/70 bg-clip-text text-transparent">
            Secure Proxy Manager
          </h1>
          <p className="text-sm text-muted-foreground">Sign in to continue</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="username" className="text-sm font-medium">Username</label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="w-full glass-surface rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 focus:ring-offset-background transition-all"
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="password" className="text-sm font-medium">Password</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full glass-surface rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 focus:ring-offset-background transition-all"
            />
          </div>

          {error && (
            <p className="text-sm text-destructive animate-fade-in-up">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-primary text-primary-foreground rounded-lg text-sm font-semibold hover:bg-primary/90 transition-all disabled:opacity-50 disabled:cursor-not-allowed btn-press"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Signing in...
              </span>
            ) : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
