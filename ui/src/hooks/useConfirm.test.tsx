import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { useConfirm } from './useConfirm';

function Harness({ onResult }: { onResult: (v: boolean) => void }) {
  const { confirm, dialog } = useConfirm();
  return (
    <div>
      <button onClick={async () => onResult(await confirm({ title: 'Reset counters?', destructive: true, confirmLabel: 'Reset' }))}>
        trigger
      </button>
      {dialog}
    </div>
  );
}

describe('useConfirm', () => {
  it('opens an alertdialog and resolves true on confirm', async () => {
    const onResult = vi.fn();
    render(<Harness onResult={onResult} />);

    fireEvent.click(screen.getByText('trigger'));
    const dialog = await screen.findByRole('alertdialog', { name: 'Reset counters?' });
    expect(dialog).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Reset' }));
    await waitFor(() => expect(onResult).toHaveBeenCalledWith(true));
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });

  it('renders the dialog into document.body, outside the page that opened it', async () => {
    // A position: fixed overlay inside a transformed or filtered ancestor is
    // laid out against that ancestor, not the window.
    render(<div style={{ transform: 'translateY(0)' }}><Harness onResult={vi.fn()} /></div>);
    fireEvent.click(screen.getByText('trigger'));
    const dialog = await screen.findByRole('alertdialog');
    const overlay = dialog.closest('.fixed') as HTMLElement;
    expect(overlay.parentElement).toBe(document.body);
  });

  it('resolves false on cancel and never fires the action', async () => {
    const onResult = vi.fn();
    render(<Harness onResult={onResult} />);

    fireEvent.click(screen.getByText('trigger'));
    await screen.findByRole('alertdialog');
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    await waitFor(() => expect(onResult).toHaveBeenCalledWith(false));
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });
});
