import { ClientSetup } from '../components/ClientSetup';

/**
 * /setup: opened on the device being configured, which has no dashboard
 * session. App renders it before the sign-in check; everything ClientSetup
 * reads here answers without a login (GET /api/client-setup, /wpad.dat,
 * /ca.crt).
 */
export default function PublicSetup() {
  return (
    <main className="min-h-screen bg-ground text-ink px-4 py-8">
      <div className="mx-auto w-full max-w-2xl space-y-4 page-enter">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 shrink-0 rounded-panel border border-line bg-surface-muted flex items-center justify-center">
            <img src="/logo.svg" alt="" className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight text-ink">Connect this device</h1>
            <p className="text-sm text-ink-muted">Set this device to use Secure Proxy Manager. No sign-in needed.</p>
          </div>
        </div>
        <ClientSetup />
        <p className="text-xs text-ink-muted">
          Administrators: <a href="/" className="text-accent underline underline-offset-2">sign in to the dashboard</a>.
        </p>
      </div>
    </main>
  );
}
