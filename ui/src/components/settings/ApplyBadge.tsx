/**
 * ApplyBadge: how a setting takes effect once saved (Proxy reload, DNS,
 * Live, Daily...), from the static map in lib/settingsMeta. The title and
 * the screen-reader text say what that means; nothing is drawn for a key
 * the map does not know.
 */
import { Badge } from '../ui/Badge';
import { APPLY_HELP, APPLY_LABEL, APPLY_MODE } from '../../lib/settingsMeta';

export function ApplyBadge({ setting }: { setting: string }) {
  const mode = APPLY_MODE[setting];
  if (!mode) return null;
  return (
    <Badge title={APPLY_HELP[mode]} data-apply={mode}>
      {APPLY_LABEL[mode]}
      <span className="sr-only">. {APPLY_HELP[mode]}</span>
    </Badge>
  );
}
