import axe from 'axe-core'

// The WCAG 2.x A and AA rules. axe's best-practice set is left out on purpose:
// rules such as "region" and "page-has-heading-one" judge a whole page, and a
// component rendered on its own would fail them by construction.
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

/**
 * Run axe on what a test rendered and throw on any violation, listing each
 * rule, its help text and the offending elements, so the failure says what
 * to fix. jsdom has no layout, so axe cannot measure colour contrast here;
 * tokens.test.ts checks the palette instead.
 */
export async function expectNoAxeViolations(container: Element = document.body): Promise<void> {
  const results = await axe.run(container, { runOnly: { type: 'tag', values: TAGS } })
  if (results.violations.length === 0) return
  const report = results.violations
    .map((v) => {
      const nodes = v.nodes.map((n) => `    ${n.target.join(' ')}: ${n.failureSummary?.split('\n').join(' ')}`).join('\n')
      return `  ${v.id} (${v.impact}): ${v.help}\n${nodes}`
    })
    .join('\n')
  throw new Error(`axe found ${results.violations.length} accessibility violation(s):\n${report}`)
}
