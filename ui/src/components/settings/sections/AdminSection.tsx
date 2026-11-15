/**
 * Admin and backup: the admin password, the API tokens, the sign-in limits, backup and restore,
 * the configuration history, and the maintenance actions. Nothing here is a draft: each action runs when its
 * button is pressed and reports its own result under it.
 */
import { ChangePassword } from '../ChangePassword';
import { ApiTokens } from '../ApiTokens';
import { SignInLimits } from '../SignInLimits';
import { BackupRestore, MaintenanceActions } from '../Maintenance';
import { ConfigHistory } from '../ConfigHistory';

export function AdminSection() {
  return (
    <div className="flex flex-col gap-4">
      <ChangePassword />
      <ApiTokens />
      <SignInLimits />
      <BackupRestore />
      <ConfigHistory />
      <MaintenanceActions />
    </div>
  );
}
