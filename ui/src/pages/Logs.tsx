import { Card, CardContent } from '../components/ui/card';
import { IpBadge } from '../components/IpBadge';
import { api } from '../lib/api';
import { Search, RefreshCw, FileText, Trash2, Activity, ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useState, useEffect, useRef, useMemo } from 'react';
import toast from 'react-hot-toast';
import { useQuery } from '@tanstack/react-query';
import { useAnimatedNumber } from '../hooks/useAnimatedNumber';
import type { LogEntry, LogsPageData } from '../types';

export function Logs() {
  const [searchTerm, setSearchTerm] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [realtimeLogs, setRealtimeLogs] = useState<LogEntry[]>([]);
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');
  const socketRef = useRef<WebSocket | null>(null);

  const { data, isLoading: loading, refetch: refreshLogs } = useQuery<LogsPageData>({
    queryKey: ['logs', 'page'],
    queryFn: () => api.get('logs?limit=100').then(r => r.data),
  });

  useEffect(() => {
    if (data?.data) {
      setRealtimeLogs(data.data.slice(0, 200));
    } else if (data?.logs) {
      setRealtimeLogs(data.logs.slice(0, 200));
    }
  }, [data]);

  // Setup WebSocket connection for real-time logs with auto-reconnect
  useEffect(() => {
    if (!autoRefresh) {
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
      return;
    }

    let ws: WebSocket | null = null;
    let pingInterval: ReturnType<typeof setInterval>;
    let reconnectTimeout: ReturnType<typeof setTimeout>;
    let cancelled = false;
    let retryCount = 0;
    const MAX_RETRIES = 10;

    const connect = () => {
      if (cancelled) return;
      api.get('/ws-token').then(({ data }) => {
        if (cancelled) return;

        const token = data.token;
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const hostname = window.location.hostname;
        const wsPort = (window as Window & { __WS_BACKEND_PORT__?: string }).__WS_BACKEND_PORT__
          ?? import.meta.env.VITE_WS_BACKEND_PORT
          ?? window.location.port
          ?? (window.location.protocol === 'https:' ? '443' : '80');
        const socketUrl = `${wsProtocol}//${hostname}:${wsPort}/api/ws/logs?token=${encodeURIComponent(token)}`;

        ws = new WebSocket(socketUrl);
        socketRef.current = ws;
        setWsStatus('connecting');

        ws.onopen = () => {
          setWsStatus('connected');
          retryCount = 0;
          pingInterval = setInterval(() => {
            if (ws?.readyState === WebSocket.OPEN) ws.send('ping');
          }, 30000);
        };

        ws.onmessage = (event) => {
          if (event.data === 'pong') return;
          try {
            const newLog = JSON.parse(event.data);
            setRealtimeLogs(prev => [newLog, ...prev].slice(0, 200));
          } catch { /* skip */ }
        };

        ws.onclose = () => {
          setWsStatus('disconnected');
          if (pingInterval) clearInterval(pingInterval);
          if (!cancelled && retryCount < MAX_RETRIES) {
            const delay = Math.min(1000 * Math.pow(2, retryCount), 30000);
            retryCount++;
            setWsStatus('connecting');
            reconnectTimeout = setTimeout(connect, delay);
          }
        };

        ws.onerror = () => { /* onclose will fire */ };
      }).catch(() => {
        if (!cancelled && retryCount < MAX_RETRIES) {
          const delay = Math.min(1000 * Math.pow(2, retryCount), 30000);
          retryCount++;
          setWsStatus('connecting');
          reconnectTimeout = setTimeout(connect, delay);
        } else {
          setWsStatus('disconnected');
        }
      });
    };

    connect();

    return () => {
      cancelled = true;
      if (pingInterval) clearInterval(pingInterval);
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        ws.close();
      }
    };
  }, [autoRefresh]);

  const filteredLogs = useMemo(() => {
    const term = searchTerm.toLowerCase();
    if (!term) return realtimeLogs;
    return realtimeLogs.filter((log) =>
      log.destination?.toLowerCase().includes(term) ||
      log.client_ip?.includes(searchTerm) ||
      log.status?.toLowerCase().includes(term)
    );
  }, [realtimeLogs, searchTerm]);

  const stats = useMemo(() => {
    const total = realtimeLogs.length;
    const blocked = realtimeLogs.filter((l) =>
      l.status?.includes('DENIED') ||
      l.status?.includes('403') ||
      l.destination?.includes('blocked')
    ).length;
    const errors = realtimeLogs.filter((l) =>
      l.status?.includes('500') ||
      l.status?.includes('502') ||
      l.status?.includes('503') ||
      l.status?.includes('504') ||
      (l.status?.includes('ERR_') && !l.status?.includes('ERR_ACCESS_DENIED'))
    ).length;
    const success = total - blocked - errors;
    return { total, blocked, errors, success };
  }, [realtimeLogs]);

  const animTotal = useAnimatedNumber(stats.total);
  const animSuccess = useAnimatedNumber(stats.success);
  const animBlocked = useAnimatedNumber(stats.blocked);
  const animErrors = useAnimatedNumber(stats.errors);

  const [clearPending, setClearPending] = useState(false);

  const handleClearLogs = async () => {
    if (!clearPending) { setClearPending(true); return; }
    setClearPending(false);
    const loadingToast = toast.loading('Clearing logs...');
    try {
      await api.post('logs/clear');
      toast.success('Logs cleared successfully', { id: loadingToast });
      setRealtimeLogs([]);
      refreshLogs();
    } catch {
      toast.error('Failed to clear logs', { id: loadingToast });
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight bg-gradient-to-b from-white to-white/70 bg-clip-text text-transparent">Access Logs</h1>
          <p className="text-sm text-muted-foreground">Monitor real-time proxy traffic</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center px-3 py-2 rounded-lg text-sm font-medium transition-all btn-press ${autoRefresh ? 'bg-primary/15 text-primary border border-primary/20' : 'glass-surface text-foreground'}`}
          >
            <div className="relative mr-2">
              <Activity className={`w-4 h-4 ${autoRefresh && wsStatus === 'connected' ? 'animate-pulse' : ''}`} />
              {autoRefresh && wsStatus === 'connected' && (
                <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-500">
                  <div className="absolute inset-0 w-2 h-2 rounded-full bg-emerald-500 animate-status-ping" />
                </div>
              )}
            </div>
            {autoRefresh ? (wsStatus === 'connected' ? 'Live' : wsStatus === 'connecting' ? 'Connecting...' : 'Reconnecting...') : 'Live Stream'}
          </button>
          <button
            type="button"
            onClick={() => refreshLogs()}
            className="flex items-center px-3 py-2 glass-surface text-foreground rounded-lg text-sm font-medium transition-all btn-press"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${loading && !autoRefresh ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          {clearPending ? (
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={handleClearLogs}
                className="px-3 py-2 bg-destructive text-destructive-foreground rounded-lg text-sm font-medium hover:bg-destructive/90 transition-colors btn-press"
              >
                Confirm Clear
              </button>
              <button
                type="button"
                onClick={() => setClearPending(false)}
                className="px-3 py-2 glass-surface text-foreground rounded-lg text-sm font-medium transition-colors btn-press"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={handleClearLogs}
              className="flex items-center px-3 py-2 bg-destructive/10 text-destructive rounded-lg text-sm font-medium hover:bg-destructive/20 transition-colors btn-press"
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Clear All
            </button>
          )}
        </div>
      </div>

      {/* Quick Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <Card className="stagger-child" style={{ '--stagger-index': 0 } as React.CSSProperties}>
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Total Requests</p>
              <h3 className="text-2xl font-bold">{animTotal.toLocaleString()}</h3>
            </div>
            <div className="p-2.5 bg-primary/10 rounded-xl text-primary">
              <Activity className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="stagger-child" style={{ '--stagger-index': 1 } as React.CSSProperties}>
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Success</p>
              <h3 className="text-2xl font-bold text-emerald-500">{animSuccess.toLocaleString()}</h3>
            </div>
            <div className="p-2.5 bg-emerald-500/10 rounded-xl text-emerald-500">
              <CheckCircle2 className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="stagger-child" style={{ '--stagger-index': 2 } as React.CSSProperties}>
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Blocked</p>
              <h3 className="text-2xl font-bold text-orange-500">{animBlocked.toLocaleString()}</h3>
            </div>
            <div className="p-2.5 bg-orange-500/10 rounded-xl text-orange-500">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="stagger-child" style={{ '--stagger-index': 3 } as React.CSSProperties}>
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Errors</p>
              <h3 className="text-2xl font-bold text-red-500">{animErrors.toLocaleString()}</h3>
            </div>
            <div className="p-2.5 bg-red-500/10 rounded-xl text-red-500">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <div className="p-4 border-b border-white/[0.06] flex items-center">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search by IP, domain, or status..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-white/[0.02] border border-white/[0.06] rounded-lg pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 focus:ring-offset-background transition-all"
            />
          </div>
          <div className="ml-auto text-sm text-muted-foreground font-mono">
            {filteredLogs.length} entries
          </div>
        </div>
        <CardContent className="p-0">
          <div className="overflow-x-auto max-h-[600px] overflow-y-auto custom-scrollbar">
            <table className="w-full text-sm text-left relative">
              <thead className="text-[10px] text-muted-foreground uppercase tracking-wider bg-white/[0.02] border-b border-white/[0.06] sticky top-0 -webkit-backdrop-blur-sm backdrop-blur-sm z-10">
                <tr>
                  <th scope="col" className="px-6 py-3 font-medium">Timestamp</th>
                  <th scope="col" className="px-6 py-3 font-medium">Client IP</th>
                  <th scope="col" className="px-6 py-3 font-medium">Method</th>
                  <th scope="col" className="px-6 py-3 font-medium">Destination</th>
                  <th scope="col" className="px-6 py-3 font-medium">Status</th>
                  <th scope="col" className="px-6 py-3 font-medium text-right">Size</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {filteredLogs.map((log) => (
                  <tr key={log.id ?? log.timestamp} className="row-hover font-mono text-xs">
                    <td className="px-6 py-3 text-muted-foreground whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-3 text-white"><IpBadge ip={log.client_ip} /></td>
                    <td className="px-6 py-3 text-primary">{log.method}</td>
                    <td className="px-6 py-3 text-muted-foreground truncate max-w-xs" title={log.destination}>
                      {log.destination}
                    </td>
                    <td className="px-6 py-3">
                      <span className={`px-2 py-1 rounded-md text-[10px] font-medium border ${
                        log.status?.includes('DENIED') || log.status?.includes('403')
                          ? 'bg-destructive/10 text-destructive border-destructive/20'
                          : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                      }`}>
                        {log.status ?? '-'}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-right text-muted-foreground">
                      {log.bytes != null ? `${(log.bytes / 1024).toFixed(1)} KB` : '-'}
                    </td>
                  </tr>
                ))}

                {filteredLogs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-6 py-12 text-center text-muted-foreground">
                      <FileText className="w-8 h-8 mx-auto mb-3 opacity-20" />
                      No logs match your search
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
