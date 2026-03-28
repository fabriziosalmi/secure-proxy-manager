import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../ui/card';
import { Key, Eye, EyeOff } from 'lucide-react';
import toast from 'react-hot-toast';
import { api } from '../../lib/api';

export function ChangePassword() {
  const [currentPwd, setCurrentPwd] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [saving, setSaving] = useState(false);

  const isValid = currentPwd.length > 0 && newPwd.length >= 8 && newPwd === confirmPwd;
  const hasNumber = /\d/.test(newPwd);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(newPwd);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isValid || !hasNumber || !hasSpecial) return;

    setSaving(true);
    try {
      await api.post('change-password', {
        current_password: currentPwd,
        new_password: newPwd,
      });
      toast.success('Password changed successfully');
      setCurrentPwd('');
      setNewPwd('');
      setConfirmPwd('');
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Failed to change password';
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card className="bg-card/50">
      <CardHeader className="p-4 pb-2">
        <div className="flex items-center gap-2">
          <Key className="w-4 h-4 text-muted-foreground" />
          <CardTitle className="text-sm">Change Password</CardTitle>
        </div>
        <CardDescription className="text-xs">Update your admin credentials</CardDescription>
      </CardHeader>
      <CardContent className="p-4 pt-0">
        <form onSubmit={handleSubmit} className="space-y-3">
          {/* Current password */}
          <div>
            <label className="text-xs font-medium text-muted-foreground">Current Password</label>
            <div className="relative mt-1">
              <input
                type={showCurrent ? 'text' : 'password'}
                value={currentPwd}
                onChange={(e) => setCurrentPwd(e.target.value)}
                autoComplete="current-password"
                className="w-full bg-background border border-border rounded-md px-3 py-1.5 text-sm pr-8 focus:outline-none focus:ring-1 focus:ring-primary"
              />
              <button type="button" onClick={() => setShowCurrent(!showCurrent)} className="absolute right-2 top-1.5 text-muted-foreground hover:text-foreground">
                {showCurrent ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* New password */}
          <div>
            <label className="text-xs font-medium text-muted-foreground">New Password</label>
            <div className="relative mt-1">
              <input
                type={showNew ? 'text' : 'password'}
                value={newPwd}
                onChange={(e) => setNewPwd(e.target.value)}
                autoComplete="new-password"
                className="w-full bg-background border border-border rounded-md px-3 py-1.5 text-sm pr-8 focus:outline-none focus:ring-1 focus:ring-primary"
              />
              <button type="button" onClick={() => setShowNew(!showNew)} className="absolute right-2 top-1.5 text-muted-foreground hover:text-foreground">
                {showNew ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
            {newPwd.length > 0 && (
              <div className="flex gap-2 mt-1.5">
                <span className={`text-[10px] px-1.5 py-0.5 rounded ${newPwd.length >= 8 ? 'bg-emerald-500/10 text-emerald-500' : 'bg-destructive/10 text-destructive'}`}>
                  {newPwd.length >= 8 ? '✓' : '✗'} 8+ chars
                </span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded ${hasNumber ? 'bg-emerald-500/10 text-emerald-500' : 'bg-destructive/10 text-destructive'}`}>
                  {hasNumber ? '✓' : '✗'} number
                </span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded ${hasSpecial ? 'bg-emerald-500/10 text-emerald-500' : 'bg-destructive/10 text-destructive'}`}>
                  {hasSpecial ? '✓' : '✗'} special
                </span>
              </div>
            )}
          </div>

          {/* Confirm */}
          <div>
            <label className="text-xs font-medium text-muted-foreground">Confirm New Password</label>
            <input
              type="password"
              value={confirmPwd}
              onChange={(e) => setConfirmPwd(e.target.value)}
              autoComplete="new-password"
              className={`w-full mt-1 bg-background border rounded-md px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-primary ${
                confirmPwd && confirmPwd !== newPwd ? 'border-destructive' : 'border-border'
              }`}
            />
            {confirmPwd && confirmPwd !== newPwd && (
              <p className="text-[10px] text-destructive mt-0.5">Passwords do not match</p>
            )}
          </div>

          <button
            type="submit"
            disabled={!isValid || !hasNumber || !hasSpecial || saving}
            className="w-full py-1.5 bg-primary text-primary-foreground rounded-md text-xs font-medium hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {saving ? 'Changing...' : 'Change Password'}
          </button>
        </form>
      </CardContent>
    </Card>
  );
}
