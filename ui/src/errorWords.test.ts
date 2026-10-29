import { describe, it, expect } from 'vitest'

// An error state says what is missing in words; the request that failed is
// a detail under it (components/ui/Unavailable). "Not reported:
// analytics/coverage did not answer." and "<p>GET /api/cache/statistics did
// not answer.</p>" led with a path. Sources are read as text through Vite.
const sources = import.meta.glob<string>(['./**/*.{ts,tsx}', '!./**/*.test.{ts,tsx}'], {
  query: '?raw',
  import: 'default',
  eager: true,
})

const PATH_FIRST = [
  /Not reported: [a-z][a-z0-9-]*\/[^\s]* did not answer/,
  /[>'"`]GET \/api\/[^<'"`]* did not answer/,
]

describe('error states', () => {
  it('never lead with the endpoint that failed', () => {
    const offenders: string[] = []
    for (const [file, text] of Object.entries(sources)) {
      if (file.endsWith('/Unavailable.tsx')) continue
      for (const line of text.split('\n')) {
        if (PATH_FIRST.some((re) => re.test(line))) offenders.push(`${file}: ${line.trim()}`)
      }
    }
    expect(Object.keys(sources).length).toBeGreaterThan(50)
    expect(offenders).toEqual([])
  })
})
