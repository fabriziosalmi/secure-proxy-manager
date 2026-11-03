/**
 * The items of "Needs attention" (lib/attention) that need it, at the top of
 * the Overview page, where an admin lands: Settings, Overview lists them all,
 * with the choices worth knowing. Each links to the Settings section that
 * fixes it.
 */
import { Link } from 'react-router';
import type { AttentionItem } from '../../lib/attention';
import { sectionPath } from '../../lib/settingsMeta';
import { Notice } from '../ui/Notice';

export function attentionNotices(items: AttentionItem[]) {
  return items
    .filter((a) => a.posture === 'needs-attention')
    .map((a) => (
      <Notice
        key={`attention-${a.id}`}
        tone="warning"
        title={a.title}
        action={a.section && a.action
          ? <Link to={sectionPath(a.section)} className="underline-offset-2 hover:underline">{a.action}</Link>
          : undefined}
      >
        {a.body}
      </Notice>
    ));
}
