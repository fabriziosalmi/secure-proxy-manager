import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Sanitize a URL that comes from the API before using it as a link `href`.
 * Only absolute http/https URLs are allowed through; anything else (a
 * `javascript:`/`data:` scheme, a malformed value, or undefined) collapses to
 * `'#'` so a compromised/misconfigured backend can't inject a script URL.
 */
export function safeExternalUrl(url?: string | null): string {
  if (!url) return '#'
  try {
    const u = new URL(url)
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : '#'
  } catch {
    return '#'
  }
}

/**
 * Parse a backend timestamp. SQLite `datetime('now')` yields
 * "2026-06-04 14:30:00": UTC, with no zone marker, which `new Date` would read
 * as local time. An ISO string that already carries a `T` is left as it is.
 */
export function parseUtc(ts: string): Date {
  return new Date(ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z')
}

/** "12s ago" / "5m ago" / "3h ago" / "2d ago"; '—' when empty, the input when unparseable. */
export function relative(ts: string): string {
  if (!ts) return '—'
  const d = parseUtc(ts).getTime()
  if (Number.isNaN(d)) return ts
  const s = Math.max(0, Math.round((Date.now() - d) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.round(h / 24)}d ago`
}
