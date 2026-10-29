import { describe, it, expect } from 'vitest'

// A placeholder that is an example value must read as one. "acme-v02.api.
// letsencrypt.org", in the monospace of the field at 4.97:1, looked like a
// destination already typed in the Egress allowlist form. Every example now
// starts with "e.g."; a placeholder that is an instruction ("Search ...",
// "Why it is blocked") is not an example. Sources are read as text through
// Vite, as styles.test.ts does.

const sources = import.meta.glob<string>(['./**/*.{ts,tsx}', '!./**/*.test.{ts,tsx}'], {
  query: '?raw',
  import: 'default',
  eager: true,
})

const INSTRUCTION = /^(Search|Filter|What|Why|At least|Type)\b/

describe('placeholders', () => {
  it('writes every example value as "e.g. ..."', () => {
    const offenders: string[] = []
    let seen = 0
    for (const [file, text] of Object.entries(sources)) {
      // placeholder="...", placeholder: '...', placeholder={'...'}, and both arms of a ternary.
      for (const m of text.matchAll(/placeholder(?:=\{?|:\s*)([^\n]*)/g)) {
        for (const lit of m[1].matchAll(/(['"`])((?:(?!\1).)*)\1/g)) {
          const value = lit[2]
          if (!value || INSTRUCTION.test(value) || /^[a-z_]+$/.test(value) || value.startsWith('${')) continue
          seen += 1
          if (!value.startsWith('e.g. ')) offenders.push(`${file}: ${value}`)
        }
      }
    }
    expect(seen).toBeGreaterThan(5)
    expect(offenders).toEqual([])
  })
})
