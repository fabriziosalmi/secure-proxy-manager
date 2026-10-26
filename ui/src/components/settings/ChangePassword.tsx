/**
 * Change the admin password (POST /api/change-password). The change ends
 * every session issued before it, this one included; the response carries a
 * fresh token so this session continues. The result is shown under the form,
 * with the backend's own message when it refuses.
 */
import { useId, useState, type FormEvent } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { api, getErrorMessage, setAuthToken } from '../../lib/api';
import { validatePassword } from '../../lib/validation';
import { cn } from '../../lib/utils';
import { Section } from '../ui/Section';
import { Button, IconButton } from '../ui/Button';

const INPUT = 'h-9 w-full min-w-0 rounded-control border bg-surface px-3 text-sm text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent';

function PasswordInput({ id, label, value, onChange, autoComplete, describedBy, invalid, reveal }: {
  id: string; label: string; value: string; onChange: (v: string) => void; autoComplete: string;
  describedBy?: string; invalid?: boolean; reveal?: boolean;
}) {
  const [shown, setShown] = useState(false);
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-ink">{label}</label>
      <div className="flex items-center gap-1">
        <input
          id={id}
          type={shown ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          className={cn(INPUT, invalid ? 'border-danger-line' : 'border-line-strong')}
        />
        {reveal && (
          <IconButton
            aria-label={shown ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`}
            icon={shown ? <EyeOff /> : <Eye />}
            onClick={() => setShown(!shown)}
          />
        )}
      </div>
    </div>
  );
}

type Result = { ok: boolean; text: string } | null;

export function ChangePassword() {
  const id = useId();
  const [currentPwd, setCurrentPwd] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<Result>(null);

  // The shared, tested rule (lib/validation), not a private copy of it.
  const { hasLength, hasNumber, hasSpecial } = validatePassword(newPwd);
  const mismatch = confirmPwd !== '' && confirmPwd !== newPwd;
  const isValid = currentPwd.length > 0 && hasLength && hasNumber && hasSpecial && newPwd === confirmPwd;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!isValid || saving) return;
    setSaving(true);
    setResult(null);
    try {
      const res = await api.post('change-password', { current_password: currentPwd, new_password: newPwd });
      const fresh = (res.data as { access_token?: string } | undefined)?.access_token;
      if (fresh) setAuthToken(fresh);
      setResult({ ok: true, text: 'Password changed. Every other session was signed out; this one continues.' });
      setCurrentPwd('');
      setNewPwd('');
      setConfirmPwd('');
    } catch (err) {
      setResult({ ok: false, text: `Not changed: ${getErrorMessage(err, 'the backend did not answer')}.` });
    } finally {
      setSaving(false);
    }
  };

  const rules: [boolean, string][] = [[hasLength, 'at least 8 characters'], [hasNumber, 'a number'], [hasSpecial, 'a special character']];

  return (
    <Section level={3} title="Admin password" description="The password of the dashboard account. The proxy login, if it is on, uses its own username and password, set under Clients and access.">
      <form onSubmit={(e) => void handleSubmit(e)} className="flex flex-col gap-4">
        <div className="grid gap-4 md:grid-cols-3">
          <PasswordInput id={`${id}-current`} label="Current Password" value={currentPwd} onChange={setCurrentPwd} autoComplete="current-password" reveal />
          <PasswordInput id={`${id}-new`} label="New Password" value={newPwd} onChange={setNewPwd} autoComplete="new-password" describedBy={`${id}-rules`} reveal />
          <PasswordInput id={`${id}-confirm`} label="Confirm New Password" value={confirmPwd} onChange={setConfirmPwd} autoComplete="new-password" describedBy={mismatch ? `${id}-mismatch` : undefined} invalid={mismatch} />
        </div>
        <ul id={`${id}-rules`} aria-label="Password rules" className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
          {rules.map(([met, text]) => (
            <li key={text} className={newPwd === '' ? 'text-ink-muted' : met ? 'text-success' : 'text-danger'}>
              {newPwd === '' ? 'Needs' : met ? 'Has' : 'Missing'} {text}
            </li>
          ))}
        </ul>
        {mismatch && <p id={`${id}-mismatch`} className="text-sm text-danger">The two new passwords do not match.</p>}
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" variant="primary" disabled={!isValid || saving}>{saving ? 'Changing...' : 'Change Password'}</Button>
          <p role="status" className={cn('text-sm', result?.ok ? 'text-success' : 'text-danger')}>{result?.text}</p>
        </div>
      </form>
    </Section>
  );
}
