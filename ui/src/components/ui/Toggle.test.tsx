import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { Toggle } from './Toggle';

describe('Toggle', () => {
  it('exposes role=switch with aria-checked reflecting state', () => {
    const { rerender } = render(<Toggle checked={false} onChange={() => {}} label="WAF" />);
    const sw = screen.getByRole('switch', { name: 'WAF' });
    expect(sw).toHaveAttribute('aria-checked', 'false');
    rerender(<Toggle checked={true} onChange={() => {}} label="WAF" />);
    expect(screen.getByRole('switch', { name: 'WAF' })).toHaveAttribute('aria-checked', 'true');
  });

  it('emits the toggled value on click', () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} label="WAF" />);
    fireEvent.click(screen.getByRole('switch', { name: 'WAF' }));
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it('is a real button, so keyboard (Space/Enter) activates it natively', () => {
    const onChange = vi.fn();
    render(<Toggle checked={true} onChange={onChange} label="WAF" />);
    const sw = screen.getByRole('switch', { name: 'WAF' });
    expect(sw.tagName).toBe('BUTTON');
    expect(sw).toHaveAttribute('type', 'button');
    fireEvent.click(sw); // jsdom maps Space/Enter on a button to a click
    expect(onChange).toHaveBeenCalledWith(false);
  });
});
