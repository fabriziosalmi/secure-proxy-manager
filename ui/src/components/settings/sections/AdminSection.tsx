/**
 * Admin and backup: the admin password, backup and restore, and the
 * maintenance actions. Nothing here is a draft: each action runs when its
 * button is pressed and reports its own result under it.
 */
import { ChangePassword } from '../ChangePassword';
import { BackupRestore, MaintenanceActions } from '../Maintenance';

export function AdminSection() {
  return (
    <div className="flex flex-col gap-4">
      <ChangePassword />
      <BackupRestore />
      <MaintenanceActions />
    </div>
  );
}
