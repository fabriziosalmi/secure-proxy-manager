import axe from 'axe-core'

// The WCAG 2.x A and AA rules. axe's best-practice set is left out on purpose:
// rules such as "region" and "page-has-heading-one" judge a whole page, and a
// component rendered on its own would fail them by construction.
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

// jsdom does not implement HTMLCanvasElement.getContext('2d'), which causes
// axe's _isIconLigature helper inside label-content-name-mismatch to throw and
// skip the rule. Provide a minimal 2d stub when running under jsdom.
function ensureCanvasStub(): void {
  if (typeof HTMLCanvasElement === 'undefined' || typeof navigator === 'undefined') return
  if (!/jsdom/i.test(navigator.userAgent)) return
  if ((HTMLCanvasElement.prototype.getContext as unknown as { __stubbed?: boolean }).__stubbed) return
  const stub = function (this: HTMLCanvasElement) {
    return {
      canvas: this,
      font: '',
      textAlign: 'left',
      textBaseline: 'top',
      measureText: (s: string) => ({ width: String(s).length * 10 }),
      fillText: () => {},
      clearRect: () => {},
      getImageData: (_x: number, _y: number, w: number, h: number) => ({
        data: new Uint8ClampedArray(Math.max(4, Math.ceil(w) * Math.ceil(h) * 4)).fill(255),
      }),
    } as unknown as RenderingContext
  } as unknown as typeof HTMLCanvasElement.prototype.getContext & { __stubbed?: boolean }
  stub.__stubbed = true
  HTMLCanvasElement.prototype.getContext = stub
}

/**
 * Run axe on what a test rendered and throw on any violation, listing each
 * rule, its help text and the offending elements, so the failure says what
 * to fix. jsdom has no layout, so axe cannot measure colour contrast here;
 * tokens.test.ts checks the palette instead.
 */
export async function expectNoAxeViolations(container: Element = document.body): Promise<void> {
  ensureCanvasStub()
  const hasMain = container.querySelector('main') !== null || container.tagName === 'MAIN'
  // axe's "region" rule uses selector "body *", so when a test renders a full
  // shell containing <main>, run against document.body so content outside
  // landmarks (like an unlabelled sidebar div) is checked too.
  const context = hasMain ? document.body : container
  const options = {
    runOnly: { type: 'tag' as const, values: TAGS },
    rules: {
      'label-content-name-mismatch': { enabled: true },
      'landmark-unique': { enabled: true },
      ...(hasMain ? { region: { enabled: true } } : {}),
    },
  }
  // One run: component tests load no stylesheet, so toggling the dark class
  // changes nothing axe can see. Contrast in both themes is tokens.test.ts's job.
  const results = await axe.run(context, options)
  if (results.violations.length === 0) return
  const report = results.violations
    .map((v) => {
      const nodes = v.nodes.map((n) => `    ${n.target.join(' ')}: ${n.failureSummary?.split('\n').join(' ')}`).join('\n')
      return `  ${v.id} (${v.impact}): ${v.help}\n${nodes}`
    })
    .join('\n')
  throw new Error(`axe found ${results.violations.length} accessibility violation(s):\n${report}`)
}
