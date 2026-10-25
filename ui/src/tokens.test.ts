import { describe, it, expect } from 'vitest'
import css from './index.css?raw'

// The design tokens live as --ds-* variables in index.css, one block for the
// light theme (:root) and one for dark (.dark). These tests read that file,
// so a token edited into an unreadable pair fails here before anyone sees it.

function block(selector: string): Record<string, string> {
  const start = css.indexOf(`${selector} {\n    --background`)
  if (start < 0) throw new Error(`no ${selector} token block in index.css`)
  const body = css.slice(start, css.indexOf('}', start))
  const out: Record<string, string> = {}
  for (const m of body.matchAll(/--ds-([a-z0-9-]+):\s*(#[0-9A-Fa-f]{6});/g)) out[m[1]] = m[2]
  return out
}

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  })
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

// [foreground token, background token, minimum ratio]. 4.5:1 is WCAG 1.4.3
// for text; 3:1 is 1.4.11 for a bar or dot that carries meaning on its own.
const TEXT_PAIRS: [string, string, number][] = [
  ['text', 'surface', 4.5], ['text', 'ground', 4.5], ['text', 'surface-muted', 4.5],
  ['text-secondary', 'surface', 4.5], ['text-secondary', 'surface-muted', 4.5],
  ['muted', 'surface', 4.5], ['muted', 'ground', 4.5], ['muted', 'surface-muted', 4.5],
  ['subtle', 'surface', 4.5], ['subtle', 'ground', 4.5],
  ['accent', 'surface', 4.5], ['accent', 'ground', 4.5], ['accent', 'accent-subtle', 4.5],
  ['accent-foreground', 'accent-solid', 4.5], ['accent-foreground', 'accent-solid-hover', 4.5],
  ['danger', 'surface', 4.5], ['danger', 'ground', 4.5], ['danger', 'danger-bg', 4.5],
  ['warning', 'surface', 4.5], ['warning', 'warning-bg', 4.5], ['warning-text', 'warning-bg', 4.5],
  ['success', 'surface', 4.5], ['success', 'success-bg', 4.5],
  ['danger-strong', 'surface', 3],
  // Pairs the shared components draw: neutral Badge, the pressed
  // SegmentedControl option, the info Notice, the sidebar's active item.
  ['muted', 'border-subtle', 4.5], ['surface', 'text', 4.5], ['text', 'accent-subtle', 4.5],
  ['subtle', 'surface-muted', 4.5],
]

describe('design tokens', () => {
  const light = block(':root')
  const dark = block('.dark')

  it('defines every token in both themes', () => {
    expect(Object.keys(light).length).toBeGreaterThan(20)
    expect(Object.keys(dark).sort()).toEqual(Object.keys(light).sort())
  })

  it('keeps the approved light values', () => {
    expect(light).toMatchObject({
      ground: '#F7F8FA', surface: '#FFFFFF', border: '#E4E7EC', 'border-subtle': '#F2F4F7',
      text: '#101828', 'text-secondary': '#344054', muted: '#475467', subtle: '#667085',
      accent: '#1D4ED8', 'accent-subtle': '#EFF4FF',
      danger: '#B42318', 'danger-strong': '#D92D20', 'danger-bg': '#FEF3F2', 'danger-border': '#FECDCA',
      warning: '#B54708', 'warning-bg': '#FFFAEB', 'warning-border': '#FEDF89',
      success: '#067647', 'success-bg': '#ECFDF3', 'neutral-bar': '#858F9F',
    })
  })

  for (const [theme, tokens] of [['light', block(':root')], ['dark', block('.dark')]] as const) {
    it.each(TEXT_PAIRS)(`${theme}: %s on %s reaches %s:1`, (fg, bg, min) => {
      expect(tokens[fg], `--ds-${fg}`).toBeDefined()
      expect(tokens[bg], `--ds-${bg}`).toBeDefined()
      expect(contrast(tokens[fg], tokens[bg])).toBeGreaterThanOrEqual(min)
    })
  }

  it.each([['light', 'surface'], ['light', 'ground'], ['dark', 'surface']] as const)(
    '%s neutral bars reach 3:1 on %s (WCAG 1.4.11, a bar carries meaning)', (theme, bg) => {
      const t = theme === 'light' ? block(':root') : dark
      expect(contrast(t['neutral-bar'], t[bg])).toBeGreaterThanOrEqual(3)
    })

  // The series of one chart (the Analytics page's blocks per day by rule)
  // stack in one bar, so a reader must tell them apart without hue: from
  // neutral-bar, each step is darker (light theme) or lighter (dark theme)
  // than the one before by at least 0.06 in OKLab lightness, the step the
  // data-viz method takes as visible, and each is a mark at 3:1 on the page.
  const SERIES = ['neutral-bar', 'series-1', 'series-2', 'series-3', 'series-4']
  for (const [theme, tokens, direction, grounds] of [
    ['light', light, -1, ['surface', 'ground']],
    ['dark', dark, 1, ['surface', 'ground']],
  ] as const) {
    it(`${theme}: the chart series step in lightness, ${direction < 0 ? 'darker' : 'lighter'} by 0.06 or more`, () => {
      const steps = SERIES.map((s) => {
        expect(tokens[s], `--ds-${s}`).toBeDefined()
        return oklabL(tokens[s])
      })
      for (let i = 1; i < steps.length; i++) {
        expect((steps[i] - steps[i - 1]) * direction, `${SERIES[i - 1]} to ${SERIES[i]}`).toBeGreaterThanOrEqual(0.06)
      }
    })
    it.each(SERIES.slice(1).flatMap((s) => grounds.map((g) => [s, g])))(`${theme}: %s reaches 3:1 on %s`, (s, g) => {
      expect(contrast(tokens[s], tokens[g])).toBeGreaterThanOrEqual(3)
    })
  }
})

/** OKLab lightness (0 black, 1 white) of a #RRGGBB colour. */
function oklabL(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  })
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b)
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b)
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b)
  return 0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s
}

describe('vendored fonts', () => {
  // The CSP is font-src 'self': every face must point at a file in public/.
  const files = Object.keys(import.meta.glob('../public/fonts/**/*', { query: '?url', eager: true }))
    .map((p) => p.replace('../public', ''))

  const faces = [...css.matchAll(/@font-face\s*{([^}]*)}/g)].map((m) => m[1])

  it('declares Inter and JetBrains Mono with font-display: swap', () => {
    const families = faces.map((f) => /font-family:\s*'([^']+)'/.exec(f)?.[1])
    expect(new Set(families)).toEqual(new Set(['Inter', 'JetBrains Mono']))
    for (const f of faces) expect(f).toMatch(/font-display:\s*swap/)
  })

  it('serves every face from a vendored woff2 with its licence beside it', () => {
    expect(faces.length).toBeGreaterThan(0)
    for (const f of faces) {
      const url = /url\('([^']+)'\)/.exec(f)?.[1] ?? ''
      expect(url).toMatch(/^\/fonts\/.+\.woff2$/)
      expect(files).toContain(url)
      expect(files).toContain(url.replace(/[^/]+$/, 'OFL.txt'))
    }
  })

  it('uses them as the sans and mono stacks', () => {
    expect(css).toMatch(/--font-sans:\s*'Inter'/)
    expect(css).toMatch(/--font-mono:\s*'JetBrains Mono'/)
  })
})
