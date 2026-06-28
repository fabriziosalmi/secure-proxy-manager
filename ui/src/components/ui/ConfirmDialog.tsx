import { useModal } from '../../hooks/useModal';

export interface ConfirmOptions {
  title: string;
  body?: string;
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
  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onCancel} aria-hidden="true" />
      <div
        ref={ref}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        aria-describedby={body ? 'confirm-body' : undefined}
        className="relative w-full max-w-sm glass-surface rounded-xl border border-border/70 p-5 shadow-2xl"
      >
        <h2 id="confirm-title" className="text-sm font-semibold">{title}</h2>
        {body && <p id="confirm-body" className="mt-2 text-xs text-muted-foreground">{body}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="px-3 py-1.5 text-xs rounded-lg border border-border hover:bg-secondary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className={`px-3 py-1.5 text-xs rounded-lg text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-background ${
              destructive
                ? 'bg-destructive hover:bg-destructive/90 focus-visible:ring-destructive'
                : 'bg-primary hover:bg-primary/90 focus-visible:ring-primary'
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
