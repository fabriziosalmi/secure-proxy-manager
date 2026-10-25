// Captures the README screenshot and the docs tour video from a running
// demo stack (scripts/demo/media.sh starts it). Runs in the e2e Playwright
// image on the stack's network. Usage: node capture.mjs <base-url> <out-dir>
import { chromium } from '@playwright/test';
import { renameSync, readdirSync } from 'node:fs';

const [base, out] = process.argv.slice(2);
const user = process.env.DEMO_USER, pass = process.env.DEMO_PASS;
if (!base || !out || !user || !pass) { console.error('usage: DEMO_USER=.. DEMO_PASS=.. node capture.mjs <base> <out>'); process.exit(2); }

const viewport = { width: 1440, height: 900 };
const browser = await chromium.launch();

async function signIn(page) {
  await page.goto(base, { waitUntil: 'networkidle' });
  await page.fill('#username', user);
  await page.fill('#password', pass);
  // Wait for the sign-in to finish: the form leaves the page once the token
  // is stored. Waiting for network idle alone returned before the answer.
  await page.click('button[type="submit"]');
  await page.locator('#username').waitFor({ state: 'detached', timeout: 15_000 });
  // Appearance is a per-browser choice; the published images use the light theme.
  await page.evaluate(() => { try { localStorage.setItem('theme', 'light'); } catch { /* storage blocked */ } });
}

async function open(page, path, settle = 2500) {
  await page.goto(base + path, { waitUntil: 'networkidle' });
  // A published image of the sign-in page instead of the product is the
  // failure this script must never let through.
  if (await page.locator('#username').count()) throw new Error(`signed out at ${path}`);
  await page.waitForTimeout(settle);
}

// 1. The screenshot: the Overview, still.
{
  const ctx = await browser.newContext({ viewport, ignoreHTTPSErrors: true, colorScheme: 'light', reducedMotion: 'reduce' });
  const page = await ctx.newPage();
  await signIn(page);
  await open(page, '/', 3000);
  await page.screenshot({ path: `${out}/dashboard.png` });
  await ctx.close();
}

// 2. The tour: Overview, the access log and one blocked request, Clients
// with one device, Blacklists, Analytics. About 30 seconds.
{
  const ctx = await browser.newContext({
    viewport, ignoreHTTPSErrors: true, colorScheme: 'light',
    recordVideo: { dir: `${out}/video`, size: viewport },
  });
  const page = await ctx.newPage();
  const fail = async (err) => {
    await page.screenshot({ path: `${out}/failed.png` }).catch(() => {});
    console.error(`tour failed at ${page.url()}: ${err.message.split('\n')[0]}`);
    throw err;
  };
  try {
  await signIn(page);
  await open(page, '/', 4000);

  await open(page, '/logs', 3000);
  await page.getByRole('button', { name: 'Blocked', exact: true }).click();
  await page.waitForTimeout(2000);
  // One WAF block and the rule behind it: the details sit under the table.
  await page.getByLabel('Rule').selectOption({ label: 'WAF' });
  await page.waitForTimeout(2000);
  await page.locator('tbody tr').first().locator('button').first().click();
  const details = page.getByRole('heading', { name: 'Request details' });
  await details.waitFor({ timeout: 10_000 });
  await details.scrollIntoViewIfNeeded();
  await page.waitForTimeout(4000);
  await page.evaluate(() => window.scrollTo({ top: 0 }));

  await open(page, '/clients', 2500);
  const client = page.getByRole('button', { name: /View details for/ }).first();
  if (await client.count()) {
    await client.click();
    await page.waitForTimeout(3500);
    await page.keyboard.press('Escape');
  }

  await open(page, '/blacklists', 3000);
  await open(page, '/analytics', 4000);
  } catch (err) { await fail(err); }
  await ctx.close();
  const [file] = readdirSync(`${out}/video`);
  renameSync(`${out}/video/${file}`, `${out}/tour.webm`);
}

await browser.close();
console.log('captured dashboard.png and tour.webm');
