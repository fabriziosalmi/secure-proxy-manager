#!/usr/bin/env node
// npm audit gate with an explicit allowlist.
//
// Plain `npm audit --audit-level=high` has no ignore mechanism, so a single
// non-applicable or dev-only HIGH advisory red-gates every unrelated PR. This
// wrapper fails the build on HIGH/CRITICAL advisories EXCEPT those explicitly
// allowlisted (with a written justification) in scripts/npm-audit-allowlist.json.
// Allowlisted advisories are printed on every run — never silently dropped — so
// the exception stays visible and auditable.
//
// Usage: run from the package dir to audit (e.g. `cd ui && node ../scripts/npm-audit-gate.mjs`).
// Gates on high+critical, matching the previous `--audit-level=high` behaviour.

import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const GATED = new Set(['high', 'critical'])
const here = dirname(fileURLToPath(import.meta.url))
const allowlist = JSON.parse(readFileSync(join(here, 'npm-audit-allowlist.json'), 'utf8')).allow

// `npm audit --json` exits non-zero when it finds anything; capture regardless.
let report
try {
  report = execSync('npm audit --json', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
} catch (e) {
  report = e.stdout || ''
}
if (!report.trim()) {
  console.error('npm-audit-gate: empty audit output — treating as failure')
  process.exit(1)
}

const audit = JSON.parse(report)
const vulns = audit.vulnerabilities || {}

// Collect distinct GHSA advisories at gated severity from every `via` entry.
const found = new Map() // ghsa -> { severity, title, pkgs:Set }
for (const [pkg, v] of Object.entries(vulns)) {
  for (const via of v.via || []) {
    if (typeof via !== 'object' || !via.url) continue
    const sev = (via.severity || v.severity || '').toLowerCase()
    if (!GATED.has(sev)) continue
    const ghsa = (via.url.match(/GHSA-[0-9a-z-]+/i) || [via.url])[0]
    if (!found.has(ghsa)) found.set(ghsa, { severity: sev, title: via.title || '', pkgs: new Set() })
    found.get(ghsa).pkgs.add(pkg)
  }
}

const ignored = []
const blocking = []
for (const [ghsa, info] of found) {
  ;(ghsa in allowlist ? ignored : blocking).push({ ghsa, ...info })
}

if (ignored.length) {
  console.log(`npm-audit-gate: ${ignored.length} allowlisted advisory(ies) ignored (see scripts/npm-audit-allowlist.json):`)
  for (const a of ignored) {
    console.log(`  - [${a.severity}] ${a.ghsa} (${[...a.pkgs].join(', ')}) — ${a.title}`)
  }
}

if (blocking.length) {
  console.error(`\nnpm-audit-gate: ${blocking.length} non-allowlisted HIGH/CRITICAL advisory(ies):`)
  for (const a of blocking) {
    console.error(`  - [${a.severity}] ${a.ghsa} (${[...a.pkgs].join(', ')}) — ${a.title}`)
    console.error(`    https://github.com/advisories/${a.ghsa}`)
  }
  console.error('\nFix them, or (only if non-applicable/dev-only) add a justified entry to scripts/npm-audit-allowlist.json.')
  process.exit(1)
}

console.log(`\nnpm-audit-gate: OK — no non-allowlisted HIGH/CRITICAL advisories.`)
