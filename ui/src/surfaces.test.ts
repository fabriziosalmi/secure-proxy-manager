import { describe, it, expect } from 'vitest'
import { extractApiCalls, matchScore } from './lib/apiCalls'
import { LISTS } from './components/blacklists/lists'

// The operations docs/public/openapi.json marks as reachable from the UI
// (x-spm-surfaces contains "ui", from backend-go/internal/handlers/surfaces.go)
// are exactly the ones the UI source calls. A call the registry does not
// claim fails, and so does a claim no call backs: the registry cannot say
// the UI offers what it does not.
const sources = import.meta.glob<string>(['./**/*.{ts,tsx}', '!./**/*.test.{ts,tsx}'], {
  query: '?raw',
  import: 'default',
  eager: true,
})

type Op = { 'x-spm-surfaces'?: string[] }
// Read through Vite, not imported: the web image builds ui/ alone, without
// docs/, and the build type-checks the tests too.
const specs = Object.values(
  import.meta.glob<{ paths: Record<string, Record<string, Op>> }>('../../docs/public/openapi.json', { import: 'default', eager: true }),
)
const spec = specs[0] ?? { paths: {} }
const operations: { key: string; method: string; path: string; ui: boolean }[] = []
for (const [path, item] of Object.entries(spec.paths)) {
  for (const [method, op] of Object.entries(item)) {
    operations.push({ key: `${method.toUpperCase()} ${path}`, method: method.toUpperCase(), path, ui: !!op['x-spm-surfaces']?.includes('ui') })
  }
}

// What a variable the path starts with can hold.
const LIST_PATHS = LISTS.map((l) => l.path)
const presetType = /type PresetList = ([^;]+);/.exec(sources['./components/blacklists/QuickLists.tsx'] ?? '')
const PRESET_LISTS = [...(presetType?.[1].matchAll(/'([a-z-]+)'/g) ?? [])].map((m) => m[1])
const PREFIXES = { 'list.path': LIST_PATHS, 'l.path': LIST_PATHS, list: PRESET_LISTS }

function called() {
  const { calls, unresolved } = extractApiCalls(sources, PREFIXES, ['lib/api.ts: path'])
  const hit = new Map<string, string>()
  const nowhere: string[] = []
  for (const c of calls) {
    let best: number | null = null
    let keys: string[] = []
    for (const op of operations) {
      if (op.method !== c.method) continue
      const s = matchScore(op.path, c.path)
      if (s === null) continue
      if (best === null || s < best) {
        best = s
        keys = [op.key]
      } else if (s === best) keys.push(op.key)
    }
    if (keys.length === 0) nowhere.push(`${c.method} ${c.path} (${c.where})`)
    for (const k of keys) if (!hit.has(k)) hit.set(k, c.where)
  }
  return { hit, nowhere, unresolved }
}

describe('UI surface', () => {
  it('reads every call', () => {
    expect(specs.length).toBe(1)
    expect(PRESET_LISTS.length).toBeGreaterThan(0)
    expect(called().unresolved).toEqual([])
  })

  it('calls exactly the operations the registry marks ui', () => {
    const { hit } = called()
    const unclaimed = [...hit.entries()].filter(([k]) => !operations.find((o) => o.key === k)?.ui).map(([k, w]) => `${k} (${w})`)
    const unbacked = operations.filter((o) => o.ui && !hit.has(o.key)).map((o) => o.key)
    expect(operations.length).toBeGreaterThan(100)
    expect(unclaimed, 'called by the UI, not marked ui in surfaces.go').toEqual([])
    expect(unbacked, 'marked ui in surfaces.go, called nowhere in the UI').toEqual([])
  })

  it('calls no path the API does not have, except the source scopes the page gates to the blacklists', () => {
    // Blacklists.tsx builds .../sources/{id}/scope for any list and offers it
    // only on the two blacklists (onScope); the exceptions have no scope route.
    const allowed = new Set(['PUT /api/ip-whitelist/sources/{}/scope', 'PUT /api/domain-whitelist/sources/{}/scope'])
    expect(called().nowhere.filter((n) => !allowed.has(n.split(' (')[0]))).toEqual([])
  })
})
