import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { useModal } from '../../hooks/useModal';
import { Button } from './Button';

export interface ConfirmOptions {
  title: string;
  /** A sentence, or a block (a list of what the action changes). */
  body?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
}

/**
 * Accessible confirmation dialog (`role="alertdialog"`) with a focus trap, Escape
 * to cancel, and focus restored to the trigger on close. Driven by `useConfirm`.
 */
export function ConfirmDialog({
  title,
  body,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  destructive,
  onConfirm,
  onCancel,
}: ConfirmOptions & { onConfirm: () => void; onCancel: () => void }) {
  const ref = useModal<HTMLDivElement>(true, onCancel);
  // Into document.body, so no transformed or filtered ancestor of the page
  // that opened it can confine the overlay to its own box.
  return createPortal(
    <div className="fixed inset-0 z-120 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50" onClick={onCancel} aria-hidden="true" />
      <div
        ref={ref}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        aria-describedby={body ? 'confirm-body' : undefined}
        className="relative w-full max-w-md rounded-panel border border-line bg-surface p-5 text-ink shadow-2xl"
      >
        <h2 id="confirm-title" className="text-base font-semibold text-ink">{title}</h2>
        {body && (typeof body === 'string'
          ? <p id="confirm-body" className="mt-2 text-sm text-ink-secondary">{body}</p>
          : <div id="confirm-body" className="mt-2 text-sm text-ink-secondary">{body}</div>)}
        <div className="mt-5 flex justify-end gap-2">
          <Button onClick={onCancel}>{cancelLabel}</Button>
          <Button variant={destructive ? 'danger-outline' : 'primary'} onClick={onConfirm}>{confirmLabel}</Button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
