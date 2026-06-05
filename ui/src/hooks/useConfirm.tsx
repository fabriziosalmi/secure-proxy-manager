import { useCallback, useState } from 'react';
import { ConfirmDialog, type ConfirmOptions } from '../components/ui/ConfirmDialog';

/**
 * Promise-based confirmation: `const { confirm, dialog } = useConfirm()`, then
 * `if (!(await confirm({ title, body, destructive }))) return;` in a handler, and
 * render `{dialog}` once in the component. Replaces fire-immediately destructive
 * actions and `window.confirm` with one accessible AlertDialog.
 */
export function useConfirm() {
  const [state, setState] = useState<{ opts: ConfirmOptions; resolve: (v: boolean) => void } | null>(null);

  const confirm = useCallback(
    (opts: ConfirmOptions) => new Promise<boolean>((resolve) => setState({ opts, resolve })),
    [],
  );

  const finish = (result: boolean) => {
    state?.resolve(result);
    setState(null);
  };

  const dialog = state ? (
    <ConfirmDialog {...state.opts} onConfirm={() => finish(true)} onCancel={() => finish(false)} />
  ) : null;

  return { confirm, dialog };
}
