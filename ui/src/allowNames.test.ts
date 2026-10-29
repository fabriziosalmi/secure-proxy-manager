import { describe, it, expect } from 'vitest'

// Two concepts were both "allowed": exceptions to the blacklists (never
// blocked) and the destinations default deny lets through, with "whitelist"
// and "allowlist" in between. The tabs are IP exceptions and Domain
// exceptions, the page is the Default-deny allowlist, and "whitelist" is not
// a word the UI shows. Sources are read as text through Vite; comments, API
// paths and identifiers are not text a reader sees.
const sources = import.meta.glob<string>(['./**/*.{ts,tsx}', '!./**/*.test.{ts,tsx}'], {
  query: '?raw',
  import: 'default',
  eager: true,
})

const OLD_NAMES = /(?<![\w/_-])[Ww]hitelist(?![\w/_-])|Allowed (IPs|domains)\b|[Ee]gress allowlist/

describe('allow names', () => {
  it('shows no whitelist, Allowed IPs, Allowed domains or Egress allowlist', () => {
    const offenders: string[] = []
    for (const [file, text] of Object.entries(sources)) {
      for (const line of text.split('\n')) {
        const code = line.trim()
        if (code.startsWith('//') || code.startsWith('*') || code.startsWith('/*') || code.startsWith('{/*')) continue
        // Search keywords: the old names still find the pages, and are not shown.
        if (file.endsWith('/GlobalSearch.tsx') && /^'\/[a-z]*': \[/.test(code)) continue
        if (OLD_NAMES.test(code)) offenders.push(`${file}: ${code}`)
      }
    }
    expect(Object.keys(sources).length).toBeGreaterThan(50)
    expect(offenders).toEqual([])
  })
})
