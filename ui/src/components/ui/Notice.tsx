/**
 * Notice: a banner that tells the user something about the system's state,
 * with a title, a body that explains the consequence, and an optional action
 * (usually a link to where it is fixed).
 *
 * Tones: info for neutral facts, warning for a degraded state, danger for
 * something that is blocking or broken. It is a polite live region
 * (role="status"), so a notice that appears after load is announced without
 * interrupting. The icon repeats the tone and is hidden from screen readers.
 */
import type { ReactNode } from 'react';
import { TriangleAlert, Info, OctagonAlert } from 'lucide-react';
import { cn } from '../../lib/utils';

export type NoticeTone = 'info' | 'warning' | 'danger';

const TONES: Record<NoticeTone, { box: string; icon: string; Icon: typeof Info }> = {
  info: { box: 'border-accent-line bg-accent-subtle text-ink', icon: 'text-accent', Icon: Info },
  warning: { box: 'border-warning-line bg-warning-subtle text-warning-ink', icon: 'text-warning', Icon: TriangleAlert },
  danger: { box: 'border-danger-line bg-danger-subtle text-danger', icon: 'text-danger', Icon: OctagonAlert },
};

export interface NoticeProps {
  title: string;
  tone?: NoticeTone;
  children?: ReactNode;
  action?: ReactNode;
  className?: string;
}

export function Notice({ title, tone = 'info', children, action, className }: NoticeProps) {
  const t = TONES[tone];
  return (
    <div role="status" data-tone={tone} className={cn('flex items-start gap-3 rounded-[10px] border px-4 py-3.5', t.box, className)}>
      <t.Icon aria-hidden="true" className={cn('mt-px h-5 w-5 shrink-0', t.icon)} strokeWidth={1.75} />
      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <p className="text-sm font-semibold">{title}</p>
        {children && <div className="text-sm leading-5">{children}</div>}
      </div>
      {action && <div className="shrink-0 text-sm font-semibold">{action}</div>}
    </div>
  );
}
