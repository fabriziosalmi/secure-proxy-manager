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
