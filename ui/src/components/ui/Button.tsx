/**
 * Button and IconButton: the only buttons new UI should draw.
 *
 * Variants: primary (one per view, the main action), secondary (everything
 * else), danger-outline (an action that removes or stops something; red is
 * never decoration) and ghost (low-emphasis, toolbars). Sizes md (36px) and
 * sm (32px). type defaults to "button", so a button inside a form never
 * submits it by accident.
 *
 * IconButton has no visible text, so its aria-label is required by the type:
 * an icon alone is not an accessible name. The label is also the tooltip.
 */
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { cn } from '../../lib/utils';

export type ButtonVariant = 'primary' | 'secondary' | 'danger-outline' | 'ghost';
export type ButtonSize = 'sm' | 'md';

const BASE =
  'inline-flex items-center justify-center gap-1.5 shrink-0 whitespace-nowrap rounded-control border font-semibold ' +
  'transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 ' +
  'focus-visible:ring-offset-surface disabled:cursor-not-allowed disabled:opacity-50';

const VARIANTS: Record<ButtonVariant, string> = {
  primary: 'border-accent-solid bg-accent-solid text-accent-foreground hover:enabled:bg-accent-solid-hover hover:enabled:border-accent-solid-hover',
  secondary: 'border-line-strong bg-surface text-ink-secondary hover:enabled:bg-surface-muted hover:enabled:text-ink',
  'danger-outline': 'border-danger-line bg-surface text-danger hover:enabled:bg-danger-subtle',
  ghost: 'border-transparent bg-transparent text-ink-muted hover:enabled:bg-surface-muted hover:enabled:text-ink',
};

const SIZES: Record<ButtonSize, string> = {
  md: 'h-9 px-3.5 text-sm',
  sm: 'h-8 px-3 text-[13px]',
};

const ICON_SIZES: Record<ButtonSize, string> = {
  md: 'h-9 w-9',
  sm: 'h-8 w-8',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** An icon drawn before the label; it is hidden from assistive technology. */
  icon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', icon, type = 'button', className, children, ...rest },
  ref,
) {
  return (
    <button ref={ref} type={type} className={cn(BASE, VARIANTS[variant], SIZES[size], className)} {...rest}>
      {icon && <span aria-hidden="true" className="inline-flex shrink-0 [&>svg]:h-4 [&>svg]:w-4">{icon}</span>}
      {children}
    </button>
  );
});

export interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children' | 'aria-label'> {
  /** Required: the button's accessible name and its tooltip. */
  'aria-label': string;
  icon: ReactNode;
  variant?: ButtonVariant;
  size?: ButtonSize;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { variant = 'ghost', size = 'md', icon, type = 'button', className, title, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      title={title ?? rest['aria-label']}
      className={cn(BASE, VARIANTS[variant], ICON_SIZES[size], 'px-0', className)}
      {...rest}
    >
      <span aria-hidden="true" className="inline-flex [&>svg]:h-[18px] [&>svg]:w-[18px]">{icon}</span>
    </button>
  );
});
