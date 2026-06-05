import { render, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { useModal } from './useModal';

function Dialog({ open, onClose }: { open: boolean; onClose?: () => void }) {
  const ref = useModal<HTMLDivElement>(open, onClose);
  if (!open) return null;
  return (
    <div ref={ref} role="dialog">
      <button>one</button>
      <button>two</button>
    </div>
  );
}

describe('useModal', () => {
  it('closes on Escape when onClose is provided', () => {
    const onClose = vi.fn();
    render(<Dialog open onClose={onClose} />);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('is inert on Escape when no onClose is given (non-dismissible gate)', () => {
    render(<Dialog open />);
    // Must not throw.
    expect(() => fireEvent.keyDown(document, { key: 'Escape' })).not.toThrow();
  });

  it('does nothing when closed', () => {
    const onClose = vi.fn();
    render(<Dialog open={false} onClose={onClose} />);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).not.toHaveBeenCalled();
  });
});
