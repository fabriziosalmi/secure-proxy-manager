import { describe, it, expect } from 'vitest'
import css from './index.css?raw'

// Two CSS mistakes that a component test cannot see, because jsdom has no
// layout and does not resolve colours. Sources are read as text through
// Vite, so this needs no Node types in the app build.

const sources = import.meta.glob<string>(['./**/*.{ts,tsx}', '!./**/*.test.{ts,tsx}'], {
  query: '?raw',
  import: 'default',
  eager: true,
})

describe('styles', () => {
  it('never defines or paints with a variable that holds bare HSL components', () => {
    // --card was "0 0% 100%", the components hsl() was built from in --color-card.
    // bg-(--card) compiled to background: var(--card), which is not a colour,
    // so the Clients drawer had no background and the table showed through.
    const bare = new Set(
      [...css.matchAll(/(--[a-z0-9-]+):\s*\d+(?:\.\d+)?\s+\d+(?:\.\d+)?%\s+\d+(?:\.\d+)?%\s*;/g)].map((m) => m[1]),
    )
    expect([...bare]).toEqual([])
    const offenders: string[] = []
    expect(Object.keys(sources).length).toBeGreaterThan(20)
    for (const [file, text] of Object.entries(sources)) {
      for (const m of text.matchAll(/\b(?:bg|text|border|fill|stroke|ring|outline|from|to|via)-\((--[a-z0-9-]+)\)/g)) {
        if (bare.has(m[1])) offenders.push(`${file}: ${m[0]}`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('page entrance animations end without a transform', () => {
    // page-enter keeps its last frame (fill-mode both). A final transform
    // other than none, even translateY(0), makes the element the containing
    // block of its position: fixed descendants, so the Clients drawer and the
    // dialogs opened from a page were laid out inside the page box instead of
    // the viewport.
    for (const utility of ['page-enter']) {
      const body = css.match(new RegExp(`@utility ${utility} \\{([^}]*)\\}`))?.[1] ?? ''
      const name = body.match(/animation:\s*([a-z0-9-]+)/)?.[1]
      expect(name, utility).toBeTruthy()
      const frames = css.match(new RegExp(`@keyframes ${name} \\{([\\s\\S]*?)\\n  \\}`))?.[1] ?? ''
      const last = frames.match(/(?:to|100%)\s*\{([^}]*)\}/)?.[1] ?? ''
      const transform = last.match(/transform:\s*([^;]+);/)?.[1]?.trim()
      expect(transform === undefined || transform === 'none', `${utility} ends on transform: ${transform}`).toBe(true)
    }
  })

  it('paints the search and confirm dialogs on an opaque surface', () => {
    // Both used glass-surface, a translucent panel, and the shadcn-era
    // text-muted-foreground and bg-secondary. Over the dimmed page the search
    // panel read as grey on grey, its placeholder and hints barely visible.
    for (const file of ['./components/GlobalSearch.tsx', './components/ui/ConfirmDialog.tsx']) {
      const text = sources[file]
      expect(text, file).toBeTruthy()
      expect(text, file).toMatch(/\bbg-surface\b/)
      for (const stale of ['glass-surface', 'text-muted-foreground', 'bg-secondary', 'backdrop-blur']) {
        expect(text.includes(stale), `${file} uses ${stale}`).toBe(false)
      }
    }
  })

  it('uses only design-system tokens in source files (no legacy shadcn or raw Tailwind colour classes)', () => {
    const legacy =
      /\b(?:text-muted-foreground|bg-secondary|border-border|text-primary|bg-primary|glass-surface|text-foreground|bg-background|text-destructive|bg-card|(?:text|bg|border)-(?:emerald|red|blue|orange|amber|green|yellow|purple|cyan)-\d{3})\b/g
    const offenders: string[] = []
    for (const [file, text] of Object.entries(sources)) {
      const matches = [...text.matchAll(legacy)].map((m) => m[0])
      if (matches.length > 0) {
        offenders.push(`${file} (${matches.length}): ${[...new Set(matches)].join(', ')}`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('defines no unused classes, @utility rules, or legacy CSS variables in index.css', () => {
    // Documented exceptions:
    // - .dark: theme class toggled on document.documentElement by ThemeProvider
    // - space-y-*: wildcard @utility that overrides Tailwind v4 space-y-<n>
    const ALLOWED_EXCEPTIONS = new Set(['dark', 'space-y-*'])

    const allSourceText = Object.values(sources)
      .map((s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, ''))
      .join('\n')

    const cssWithoutComments = css.replace(/\/\*[\s\S]*?\*\//g, '')
    const definedUtilities = [...cssWithoutComments.matchAll(/@utility\s+([a-zA-Z0-9_-]+(?:\*)?)/g)].map((m) => m[1])
    const definedClasses = [...cssWithoutComments.matchAll(/(?:^|[\s,:(])\.([a-zA-Z_-][a-zA-Z0-9_-]*)/gm)].map(
      (m) => m[1],
    )

    const unused: string[] = []
    for (const name of new Set([...definedUtilities, ...definedClasses])) {
      if (ALLOWED_EXCEPTIONS.has(name)) continue
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const re = new RegExp(`\\b${escaped}\\b`)
      if (!re.test(allSourceText)) {
        unused.push(name)
      }
    }

    // Legacy glassmorphism and shadcn HSL variables must not remain in index.css
    const legacyVars = [...cssWithoutComments.matchAll(/(--(?:glass-[a-z0-9-]+|background|foreground|card(?:-foreground)?|popover(?:-foreground)?|primary(?:-foreground)?|secondary(?:-foreground)?|muted(?:-foreground)?|destructive(?:-foreground)?|border|input|ring|radius))\s*:/g)].map((m) => m[1])
    unused.push(...new Set(legacyVars))

    expect(unused).toEqual([])
  })
})
