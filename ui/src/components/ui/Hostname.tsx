/**
 * Hostname: a host name or URL that does not break inside a label. By
 * default it may wrap only after a dot or a slash (a <wbr> after each, none
 * between the two slashes of a scheme), so "gsp57-ssl-background.ls.apple.com"
 * goes onto a second line as "apple.com", not as "om". Each piece keeps its
 * hyphens on one line too: a browser breaks after a hyphen as readily as
 * after a dot. A piece longer than LONG_PIECE characters may still break, as
 * a last resort (overflow-wrap: break-word, which unlike break-all does not
 * shrink a table column to one letter), so a very long label cannot run out
 * of its box.
 *
 * truncate keeps it on one line, cut with an ellipsis, the whole name in the
 * title: for a table column whose rows must stay one line high.
 */
import { Fragment, type HTMLAttributes } from 'react';
import { cn } from '../../lib/utils';

export interface HostnameProps extends Omit<HTMLAttributes<HTMLSpanElement>, 'children'> {
  name: string;
  truncate?: boolean;
}

/** The longest piece kept on one line: 24 monospace characters fit the narrowest column that shows one (11rem at 12px). */
const LONG_PIECE = 24;

/** The name in pieces that each end after a dot or a slash, where a line may break. */
function pieces(name: string): string[] {
  return name.split(/(?<=[./])/);
}

export function Hostname({ name, truncate, className, ...rest }: HostnameProps) {
  if (truncate) {
    return <span title={name} className={cn('block min-w-0 truncate', className)} {...rest}>{name}</span>;
  }
  const parts = pieces(name);
  return (
    <span data-hostname={name} className={cn('[overflow-wrap:break-word]', className)} {...rest}>
      {parts.map((part, i) => (
        <Fragment key={i}>
          {part.length <= LONG_PIECE ? <span className="whitespace-nowrap">{part}</span> : part}
          {i < parts.length - 1 && !parts[i + 1].startsWith('/') && <wbr />}
        </Fragment>
      ))}
    </span>
  );
}
