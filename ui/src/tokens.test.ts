import { describe, it, expect } from 'vitest'
import css from './index.css?raw'

// The design tokens live as --ds-* variables in index.css, one block for the
// light theme (:root) and one for dark (.dark). These tests read that file,
// so a token edited into an unreadable pair fails here before anyone sees it.

function block(selector: string): Record<string, string> {
  const start = css.indexOf(`${selector} {\n`)
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
  // stack in one bar, one colour per group of rules. A reader must tell any
  // two apart, also with a colour vision deficiency: every pair, neutral-bar
  // included, is at least 0.12 apart in OKLab, and 0.07 apart once the
  // colours are passed through the protanopia, deuteranopia and tritanopia
  // simulations of Machado et al. (2009, severity 1). Each is a mark at 3:1
  // on the page. The four reds this replaced were 0.08 apart.
  const SERIES = ['neutral-bar', 'series-1', 'series-2', 'series-3', 'series-4']
  for (const [theme, tokens, grounds] of [
    ['light', light, ['surface', 'ground']],
    ['dark', dark, ['surface', 'ground']],
  ] as const) {
    for (const [vision, matrix, min] of VISIONS) {
      it(`${theme}: any two chart series are ${min} or more apart in OKLab with ${vision}`, () => {
        for (let i = 0; i < SERIES.length; i++) {
          for (let j = i + 1; j < SERIES.length; j++) {
            const [a, b] = [tokens[SERIES[i]], tokens[SERIES[j]]]
            expect(a, `--ds-${SERIES[i]}`).toBeDefined()
            expect(b, `--ds-${SERIES[j]}`).toBeDefined()
            expect(oklabDistance(a, b, matrix), `${SERIES[i]} and ${SERIES[j]}`).toBeGreaterThanOrEqual(min)
          }
        }
      })
    }
    it.each(SERIES.slice(1).flatMap((s) => grounds.map((g) => [s, g])))(`${theme}: %s reaches 3:1 on %s`, (s, g) => {
      expect(contrast(tokens[s], tokens[g])).toBeGreaterThanOrEqual(3)
    })
  }
})

type Matrix = [number, number, number][]

// Simulations of colour vision deficiency on linear sRGB, Machado, Oliveira
// and Fernandes (2009), severity 1.0.
const VISIONS: [string, Matrix | null, number][] = [
  ['normal vision', null, 0.12],
  ['protanopia', [[0.152286, 1.052583, -0.204868], [0.114503, 0.786281, 0.099216], [-0.003882, -0.048116, 1.051998]], 0.07],
  ['deuteranopia', [[0.367322, 0.860646, -0.227968], [0.280085, 0.672501, 0.047413], [-0.01182, 0.04294, 0.968881]], 0.07],
  ['tritanopia', [[1.255528, -0.076749, -0.178779], [-0.078411, 0.930809, 0.147602], [0.004733, 0.691367, 0.3039]], 0.07],
]

/** The linear sRGB of a #RRGGBB colour. */
function linear(hex: string): number[] {
  return [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  })
}

/** OKLab (L, a, b) of linear sRGB. */
function oklab([r, g, b]: number[]): number[] {
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b)
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b)
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b)
  return [
    0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  ]
}

/** The OKLab distance of two colours, as seen through matrix (null: normal vision). */
function oklabDistance(a: string, b: string, matrix: Matrix | null): number {
  const seen = (hex: string) => {
    const c = linear(hex)
    return oklab(matrix ? matrix.map((row) => Math.min(1, Math.max(0, row[0] * c[0] + row[1] * c[1] + row[2] * c[2]))) : c)
  }
  const [x, y] = [seen(a), seen(b)]
  return Math.hypot(x[0] - y[0], x[1] - y[1], x[2] - y[2])
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
