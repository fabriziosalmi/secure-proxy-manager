/**
 * Secure Proxy Manager — Self-Hoster E2E Test Suite
 *
 * Simulates the full onboarding → daily-use workflow of a self-hoster:
 *   Login · Dashboard · Blacklists (add / paste / URL import / geo-block / remove,
 *   sources, enforcement, tabs in the URL) · Egress allowlist · Audit log ·
 *   Logs page · Settings
 *
 * Architecture notes:
 *   - API tests run via Playwright's `request` fixture (no browser overhead)
 *   - UI tests drive real Chromium, signed in per test with a cookie session
 *     (injectAuth), as the UI signs in
 *   - Auth tests deliberately run WITHOUT token injection
 *
 * Environment variables (set in docker-compose.test.yml):
 *   BASE_URL          https://web:8443         (UI + nginx, HTTPS only)
 *   API_URL           http://backend:5000      (direct backend)
 *   TEST_USERNAME     testadmin
 *   TEST_PASSWORD     TestP@ss123!
 *   MOCK_LISTS_URL    http://mock-lists:8080   (SSRF-blocked in Docker — expected 403)
 */

import { appendFileSync } from 'node:fs';
import { test, expect, type Page, type APIRequestContext } from '@playwright/test';

// ─── Config ───────────────────────────────────────────────────────────────────

const USERNAME = process.env.TEST_USERNAME ?? 'testadmin';
const PASSWORD = process.env.TEST_PASSWORD ?? 'TestP@ss123!';
const API_URL   = process.env.API_URL        ?? 'http://localhost:5001';
const MOCK_URL  = process.env.MOCK_LISTS_URL ?? 'http://mock-lists:8080';

// RFC 5737 / RFC 2606 addresses — safe test values, never routable
const TEST_IP_1      = '192.0.2.11';
const TEST_IP_2      = '198.51.100.22';
const TEST_IP_3      = '203.0.113.33';
const TEST_CIDR      = '192.0.2.128/26';
const TEST_WHITELIST = '10.99.99.0/28';
const TEST_DOMAIN_1  = 'test-bad-actor.test';
const TEST_DOMAIN_2  = 'malware-cdn.test';
const TEST_DOMAIN_3  = 'phishing-kit.test';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Obtain a JWT token via the API. */
async function apiToken(request: APIRequestContext): Promise<string> {
  const res = await request.post('/api/auth/login', {
    data: { username: USERNAME, password: PASSWORD },
  });
  expect(res.ok(), `Login failed (${res.status()}): ${await res.text()}`).toBeTruthy();
  const { access_token: token } = (await res.json()) as { access_token: string };
  return token;
}

/**
 * Sign the page's browser context in as the UI does: a cookie session. The
 * context's request client shares the browser's cookie jar, so the HttpOnly
 * session cookie it receives is sent by the page on the next page.goto().
 */
async function injectAuth(page: Page, _request?: APIRequestContext): Promise<void> {
  const res = await page.context().request.post('/api/auth/login', {
    headers: { 'X-SPM-Session': 'cookie' },
    data: { username: USERNAME, password: PASSWORD },
  });
  expect(res.ok(), `Cookie login failed (${res.status()}): ${await res.text()}`).toBeTruthy();
}

// Mark the first-run Setup Wizard complete once for the whole run, so
// authenticated views land on the Dashboard instead of the wizard gate.
test.beforeAll(async ({ request }) => {
  const token = await apiToken(request);
  await request.post('/api/settings', {
    headers: { Authorization: `Bearer ${token}` },
    data: { wizard_completed: 'true' },
  });
});

// ─── AUTH ─────────────────────────────────────────────────────────────────────

test.describe('Authentication', () => {
  // No token injection — these tests verify the unauthenticated flow
  test.beforeEach(async ({ page }) => {
    // No session left from other tests
    await page.context().clearCookies();
    await page.addInitScript(() => { localStorage.clear(); sessionStorage.clear(); });
  });

  test('shows login form when unauthenticated', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('h1', { hasText: 'Secure Proxy Manager' })).toBeVisible();
    await expect(page.locator('#username')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeEnabled();
  });

  test('shows error for wrong credentials', async ({ page }) => {
    await page.goto('/');
    await page.fill('#username', 'wrong');
    await page.fill('#password', 'wrong');
    await page.click('button[type="submit"]');
    // The 401 interceptor must NOT reload the page during login
    await expect(page.getByRole('alert'))
      .toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Invalid username or password')).toBeVisible();
  });

  test('logs in successfully with correct credentials', async ({ page }) => {
    await page.goto('/');
    await page.fill('#username', USERNAME);
    await page.fill('#password', PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page.getByRole('heading', { level: 1, name: 'Overview' }).first()).toBeVisible({ timeout: 15_000 });
  });

  test('keeps the session token where no script in the page can read it', async ({ page }) => {
    await page.goto('/');
    await page.fill('#username', USERNAME);
    await page.fill('#password', PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page.getByRole('heading', { level: 1, name: 'Overview' }).first()).toBeVisible({ timeout: 15_000 });
    const cookie = (await page.context().cookies()).find((c) => c.name === 'spm_session');
    expect(cookie, 'the session cookie').toBeTruthy();
    expect(cookie).toMatchObject({ httpOnly: true, secure: true, sameSite: 'Strict', path: '/api' });
    const seen = await page.evaluate(() => ({
      cookie: document.cookie,
      storage: JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }),
    }));
    expect(seen.cookie).not.toContain('spm_session');
    expect(seen.storage).not.toContain(cookie!.value);
    // Signing out ends it on the server: the same cookie is refused afterwards.
    const value = cookie!.value;
    await page.getByRole('button', { name: 'Sign out' }).first().click();
    await expect(page.locator('#username')).toBeVisible({ timeout: 10_000 });
    const replay = await page.request.get('/api/session', { headers: { Cookie: `spm_session=${value}` } });
    expect(replay.status()).toBe(401);
  });

  test('submit button shows loading state', async ({ page }) => {
    await page.goto('/');
    await page.fill('#username', USERNAME);
    await page.fill('#password', PASSWORD);
    await page.route('**/api/auth/login', async route => {
      await new Promise(r => setTimeout(r, 800));
      await route.continue();
    });
    const submitBtn = page.locator('button[type="submit"]');
    await submitBtn.click();
    await expect(submitBtn).toHaveText(/Signing in/i);
  });
});

// ─── API — direct backend layer ───────────────────────────────────────────────

test.describe('API — health & auth', () => {
  test('GET /health returns 200', async ({ request }) => {
    const res = await request.get(`${API_URL}/health`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({ status: 'healthy' });
  });

  test('GET /api/health returns 200', async ({ request }) => {
    const res = await request.get('/api/health');
    expect(res.status()).toBe(200);
  });

  test('protected endpoint returns 401 without token', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/settings`);
    expect(res.status()).toBe(401);
  });

  test('POST /api/auth/login returns JWT token', async ({ request }) => {
    const res = await request.post('/api/auth/login', {
      data: { username: USERNAME, password: PASSWORD },
    });
    expect(res.ok()).toBeTruthy();
    const { access_token: token } = (await res.json()) as { access_token: string };
    expect(typeof token).toBe('string');
    expect(token.split('.').length).toBe(3); // JWT = 3 base64 segments
  });

  test('POST /api/auth/login rejects bad credentials with 401', async ({ request }) => {
    const res = await request.post('/api/auth/login', {
      data: { username: 'nobody', password: 'wrong' },
    });
    expect(res.status()).toBe(401);
  });
});

test.describe('API — CRUD: IP blacklist', () => {
  let token: string;
  let createdId: number;

  test.beforeAll(async ({ request }) => { token = await apiToken(request); });

  test('GET /api/ip-blacklist returns array', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/ip-blacklist`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = (await res.json()) as { data: unknown[] };
    expect(Array.isArray(body.data)).toBeTruthy();
  });

  test('POST /api/ip-blacklist creates entry', async ({ request }) => {
    const res = await request.post(`${API_URL}/api/ip-blacklist`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { ip: TEST_IP_1, description: 'e2e test' },
    });
    expect(res.ok() || res.status() === 400).toBeTruthy();
    if (res.ok()) {
      const body = (await res.json()) as { data?: { id?: number } };
      if (body.data?.id) createdId = body.data.id;
    }
  });

  test('GET /api/ip-blacklist contains test entry', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/ip-blacklist`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await res.json()) as { data: Array<{ ip: string }> };
    expect(body.data.some(e => e.ip === TEST_IP_1)).toBeTruthy();
  });

  test('DELETE /api/ip-blacklist/:id removes entry', async ({ request }) => {
    if (!createdId) {
      const res = await request.get(`${API_URL}/api/ip-blacklist`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const body = (await res.json()) as { data: Array<{ id: number; ip: string }> };
      createdId = body.data.find(e => e.ip === TEST_IP_1)?.id ?? 0;
    }
    if (!createdId) return;
    const del = await request.delete(`${API_URL}/api/ip-blacklist/${createdId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(del.ok()).toBeTruthy();
  });
});

test.describe('API — CRUD: domain blacklist', () => {
  let token: string;
  let createdId: number;

  test.beforeAll(async ({ request }) => { token = await apiToken(request); });

  test('POST /api/domain-blacklist creates entry', async ({ request }) => {
    const res = await request.post(`${API_URL}/api/domain-blacklist`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { domain: TEST_DOMAIN_1, description: 'e2e domain test' },
    });
    expect(res.ok() || res.status() === 400).toBeTruthy();
    if (res.ok()) {
      const body = (await res.json()) as { data?: { id?: number } };
      if (body.data?.id) createdId = body.data.id;
    }
  });

  test('GET /api/domain-blacklist contains test entry', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/domain-blacklist`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await res.json()) as { data: Array<{ domain: string }> };
    expect(body.data.some(e => e.domain === TEST_DOMAIN_1)).toBeTruthy();
  });

  test('DELETE /api/domain-blacklist/:id removes entry', async ({ request }) => {
    if (!createdId) {
      const res = await request.get(`${API_URL}/api/domain-blacklist`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const body = (await res.json()) as { data: Array<{ id: number; domain: string }> };
      createdId = body.data.find(e => e.domain === TEST_DOMAIN_1)?.id ?? 0;
    }
    if (!createdId) return;
    const del = await request.delete(`${API_URL}/api/domain-blacklist/${createdId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(del.ok()).toBeTruthy();
  });
});

test.describe('API — CRUD: IP whitelist', () => {
  let token: string;
  let createdId: number;

  test.beforeAll(async ({ request }) => { token = await apiToken(request); });

  test('POST /api/ip-whitelist creates entry', async ({ request }) => {
    const res = await request.post(`${API_URL}/api/ip-whitelist`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { ip: TEST_WHITELIST, description: 'e2e whitelist' },
    });
    expect(res.ok() || res.status() === 400).toBeTruthy();
    if (res.ok()) {
      const body = (await res.json()) as { data?: { id?: number } };
      if (body.data?.id) createdId = body.data.id;
    }
  });

  test('GET /api/ip-whitelist contains test entry', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/ip-whitelist`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await res.json()) as { data: Array<{ ip: string }> };
    expect(body.data.some(e => e.ip === TEST_WHITELIST)).toBeTruthy();
  });

  test('DELETE /api/ip-whitelist/:id removes entry', async ({ request }) => {
    if (!createdId) {
      const res = await request.get(`${API_URL}/api/ip-whitelist`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const body = (await res.json()) as { data: Array<{ id: number; ip: string }> };
      createdId = body.data.find(e => e.ip === TEST_WHITELIST)?.id ?? 0;
    }
    if (!createdId) return;
    const del = await request.delete(`${API_URL}/api/ip-whitelist/${createdId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(del.ok()).toBeTruthy();
  });
});

test.describe('API — bulk import', () => {
  let token: string;

  test.beforeAll(async ({ request }) => { token = await apiToken(request); });

  test('POST /api/blacklists/import — IP type via content', async ({ request }) => {
    const content = [TEST_IP_2, TEST_IP_3, TEST_CIDR, '# comment', 'not-an-ip'].join('\n');
    const res = await request.post(`${API_URL}/api/blacklists/import`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { type: 'ip', content },
    });
    expect(res.ok()).toBeTruthy();
    const body = (await res.json()) as { data: { added: number; skipped: number } };
    expect(body.data.added + body.data.skipped).toBeGreaterThanOrEqual(3);
  });

  test('POST /api/blacklists/import — domain type via content', async ({ request }) => {
    const content = [TEST_DOMAIN_2, TEST_DOMAIN_3, '# skip', 'not a domain!!@#'].join('\n');
    const res = await request.post(`${API_URL}/api/blacklists/import`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { type: 'domain', content },
    });
    expect(res.ok()).toBeTruthy();
    const body = (await res.json()) as { data: { added: number; skipped: number } };
    expect(body.data.added + body.data.skipped).toBeGreaterThanOrEqual(2);
  });

  test('POST /api/blacklists/import — URL source (SSRF blocks private Docker IPs — expected 403)', async ({ request }) => {
    // mock-lists resolves to a Docker-internal private IP → backend SSRF guard returns 403.
    // This test verifies the endpoint exists and the guard fires correctly.
    const res = await request.post(`${API_URL}/api/blacklists/import`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { type: 'ip', url: `${MOCK_URL}/ip-list.txt` },
    });
    // 403 = SSRF protection triggered (correct for Docker private IP)
    // 200 = mock server reachable (correct for public deployments)
    // 400/422/500 = other error also acceptable
    expect([200, 400, 403, 422, 500].includes(res.status())).toBeTruthy();
  });
});

test.describe('API — logs, stats, security score', () => {
  let token: string;

  test.beforeAll(async ({ request }) => { token = await apiToken(request); });

  test('GET /api/logs returns paginated response', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/logs?limit=10&offset=0`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = (await res.json()) as { data?: unknown[]; logs?: unknown[] };
    expect(Array.isArray(body.data ?? body.logs ?? [])).toBeTruthy();
  });

  test('GET /api/logs takes the access-log filters and refuses a malformed one', async ({ request }) => {
    const headers = { Authorization: `Bearer ${token}` };
    const ok = await request.get(`${API_URL}/api/logs?limit=5&outcome=blocked&reason=waf&q=example&include_internal=true&before_id=999999`, { headers });
    expect(ok.status()).toBe(200);
    const body = (await ok.json()) as { data: unknown[]; meta: { total: number } };
    expect(Array.isArray(body.data)).toBeTruthy();
    expect(typeof body.meta.total).toBe('number');
    const bad = await request.get(`${API_URL}/api/logs?outcome=denied`, { headers });
    expect(bad.status()).toBe(400);
  });

  test('GET /api/logs/export streams CSV with its header row', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/logs/export?outcome=blocked`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status()).toBe(200);
    expect(res.headers()['content-type']).toContain('text/csv');
    expect(res.headers()['content-disposition']).toContain('attachment');
    expect((await res.text()).split('\n')[0]).toBe('id,timestamp_utc,source_ip,internal,kind,method,destination,status,bytes,blocked,reason,reason_label,resolved_ip');
  });

  test('GET /api/logs/stats returns counts', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/logs/stats`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
  });

  test('GET /api/logs/timeline returns array', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/logs/timeline?hours=24`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
  });

  test('GET /api/security/score is retired and says so', async ({ request }) => {
    // It scored settings nothing enforced; retired routes answer 410.
    const res = await request.get(`${API_URL}/api/security/score`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status()).toBe(410);
    expect(((await res.json()) as { detail?: string }).detail).toContain('removed');
  });

  test('GET /api/cache/statistics returns data', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/cache/statistics`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
  });

  test('GET /api/settings returns settings array', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/settings`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = (await res.json()) as { data?: unknown[] };
    expect(Array.isArray(body.data)).toBeTruthy();
  });

  test('GET /api/database/export returns JSON backup', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/database/export`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json() as Record<string, unknown>;
    expect(Object.keys(body).length).toBeGreaterThan(0);
  });
});

// ─── UI — Dashboard ───────────────────────────────────────────────────────────

test.describe('UI — Dashboard', () => {
  test.beforeEach(async ({ page, request }) => { await injectAuth(page, request); });

  test('shows proxy address banner with host and port 3128', async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('h1:has-text("Overview")', { timeout: 15_000 });
    await expect(page.locator('code').filter({ hasText: '3128' }).first()).toBeVisible();
  });

  test('copy button shows confirmation on click', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    // Mock clipboard so writeText resolves immediately in headless mode
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText: () => Promise.resolve() },
        writable: true, configurable: true,
      });
    });
    await page.goto('/');
    await page.waitForSelector('h1:has-text("Overview")');
    const copyBtn = page.getByRole('button', { name: /copy proxy address/i });
    await copyBtn.click();
    // Feedback is an icon swap (Copy → Check), not a "Copied!" label.
    await expect(copyBtn.locator('svg.lucide-check')).toBeVisible({ timeout: 5_000 });
  });

  // The cards of the last 24 hours, each with a value from dashboard/summary:
  // a count, or "Not reported" when the backend did not send the field.
  // The score and the "Today" / "Total" pair are gone from this page.
  test('shows the last-24-hours cards (Client requests, Blocked, Active clients, Rules in force)', async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('h1:has-text("Overview")');
    await expect(page.getByText(/^Last 24 hours · updated \d\d:\d\d$/)).toBeVisible();
    const cards = page.getByRole('region', { name: 'Last 24 hours at a glance' });
    for (const label of ['Client requests', 'Blocked', 'Active clients', 'Rules in force']) {
      const card = cards.locator('div').filter({ has: page.getByText(label, { exact: true }) }).last();
      await expect(card).toBeVisible();
      await expect(card.locator('p').nth(1)).toHaveText(/^(\d{1,3}(,\d{3})*|Not reported)$/);
    }
    // The e2e stack runs the current backend, which sends every field.
    await expect(cards.getByText('Not reported')).toHaveCount(0);
    for (const gone of ['Score', 'Today', 'Block Rate', 'IP Rules']) {
      await expect(page.getByText(gone, { exact: true })).toHaveCount(0);
    }
  });

  test('requests per hour chart is rendered, or says there were none', async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('h1:has-text("Overview")');
    const chart = page.getByRole('region', { name: 'Requests per hour' });
    await expect(chart).toBeVisible();
    await expect(
      chart.getByRole('img', { name: /^Requests per hour, last 24 hours: / })
        .or(chart.getByText('No client requests in the last 24 hours')),
    ).toBeVisible();
  });

  test('reset counters is not on the overview', async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('h1:has-text("Overview")');
    await expect(page.getByRole('region', { name: 'Services' })).toBeVisible();
    await expect(page.getByRole('button', { name: /reset/i })).toHaveCount(0);
  });

  // Mobile.dc.html: the cards stack two by two and nothing scrolls sideways.
  test('fits a 390 px wide screen without horizontal scrolling', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/');
    await page.waitForSelector('h1:has-text("Overview")');
    await expect(page.getByRole('region', { name: 'Services' })).toBeVisible();
    const overflow = await page.evaluate(() => {
      const main = document.querySelector('main')!;
      return { doc: document.documentElement.scrollWidth - window.innerWidth, main: main.scrollWidth - main.clientWidth };
    });
    expect(overflow).toEqual({ doc: 0, main: 0 });
  });
});

// ─── UI: Access logs live feed ───────────────────────────────────────────────

test.describe('UI: Access logs', () => {
  test.beforeEach(async ({ page, request }) => { await injectAuth(page, request); });

  // A real browser fails the WebSocket handshake when it offers subprotocols
  // and the server selects none. The backend used to select none, so the live
  // feed never connected in any browser while non-browser tests passed.
  test('the live feed connects (the button reads Live)', async ({ page }) => {
    const wsErrors: string[] = [];
    page.on('console', (m) => { if (m.type() === 'error' && /WebSocket/.test(m.text())) wsErrors.push(m.text()); });
    await page.goto('/logs');
    await page.waitForSelector('h1:has-text("Access logs")', { timeout: 15_000 });
    // "Live" only once the socket is open: "Connecting" and "Reconnecting"
    // before, "Paused" when switched off.
    const live = page.getByRole('button', { name: 'Live', exact: true });
    await expect(live).toBeVisible({ timeout: 15_000 });
    await expect(live).toHaveAttribute('aria-pressed', 'true');
    expect(wsErrors).toEqual([]);
  });

  // The filters are in the URL, so a link opens the same view, and a change
  // is written back to it.
  test('the filters are read from the URL and written to it', async ({ page }) => {
    await page.goto('/logs?outcome=blocked&q=example');
    await page.waitForSelector('h1:has-text("Access logs")', { timeout: 15_000 });
    await expect(page.getByRole('button', { name: 'Blocked', exact: true })).toHaveAttribute('aria-pressed', 'true');
    await expect(page.getByRole('searchbox', { name: 'Search destinations' })).toHaveValue('example');
    await page.getByRole('button', { name: 'Allowed', exact: true }).click();
    await expect(page).toHaveURL(/[?&]outcome=allowed/);
    await expect(page.getByRole('table', { name: 'Access log requests' })).toBeVisible();
  });
});

// ─── UI: Clients ──────────────────────────────────────────────────────────────

test.describe('UI: Clients', () => {
  test.beforeEach(async ({ page, request }) => { await injectAuth(page, request); });

  // The client list marks the stack's own addresses, and the dashboard says
  // how many it left out of its counts.
  test('the client list and the summary say which sources are internal', async ({ request }) => {
    const token = await apiToken(request);
    const headers = { Authorization: `Bearer ${token}` };
    const list = await request.get(`${API_URL}/api/clients/statistics`, { headers });
    expect(list.ok()).toBeTruthy();
    const body = (await list.json()) as {
      data: { ip_address: string; internal: unknown; kind: unknown }[];
      meta: { total: number; internal: unknown };
    };
    expect(Array.isArray(body.data)).toBeTruthy();
    expect(typeof body.meta.internal).toBe('number');
    for (const row of body.data) {
      expect(typeof row.internal, row.ip_address).toBe('boolean');
      expect(typeof row.kind, row.ip_address).toBe('string');
    }
    expect(body.data.filter((r) => r.internal === true)).toHaveLength(body.meta.internal as number);

    const summary = await request.get(`${API_URL}/api/dashboard/summary`, { headers });
    expect(summary.ok()).toBeTruthy();
    const s = (await summary.json()) as { data: Record<string, unknown> };
    expect(typeof s.data.last_24h_internal_sources).toBe('number');
    expect(typeof s.data.last_24h_internal_requests).toBe('number');
  });

  test('shows the page from the mockup, with internal addresses hidden until the viewer shows them', async ({ page }) => {
    await page.goto('/clients');
    await expect(page.getByRole('heading', { level: 1, name: 'Clients' })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText('Devices that sent traffic through the proxy in the last 7 days.')).toBeVisible();
    await expect(page.getByRole('searchbox', { name: 'Filter clients by IP address' })).toBeVisible();

    const toggle = page.getByRole('switch', { name: /^Show internal addresses \(\d+\)$/ });
    await expect(toggle).toHaveAttribute('aria-checked', 'false');
    await expect(page.getByRole('table', { name: 'Clients in the last 7 days' })).toBeVisible();
    await expect(page.getByText(/^\d+ (client|clients) (shown|matches the filter)\./)).toBeVisible();
    // The choice is kept for this viewer across a reload.
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-checked', 'true');
    await page.reload();
    await expect(page.getByRole('switch', { name: /^Show internal addresses \(\d+\)$/ })).toHaveAttribute('aria-checked', 'true');
    await expect(page.getByText(/Internal traffic is not counted in any statistic\./)).toBeVisible();

    const connect = page.getByRole('button', { name: 'Connect a device' }).first();
    await expect(connect).toHaveAttribute('aria-expanded', 'false');
    await connect.click();
    await expect(connect).toHaveAttribute('aria-expanded', 'true');
    await expect(page.getByRole('tablist', { name: 'Operating system' })).toBeVisible();
  });

  test('fits a 390 px wide screen without horizontal scrolling', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/clients');
    await expect(page.getByRole('heading', { level: 1, name: 'Clients' })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('table', { name: 'Clients in the last 7 days' })).toBeAttached();
    const overflow = await page.evaluate(() => {
      const main = document.querySelector('main')!;
      return { doc: document.documentElement.scrollWidth - window.innerWidth, main: main.scrollWidth - main.clientWidth };
    });
    expect(overflow).toEqual({ doc: 0, main: 0 });
  });
});

// ─── UI: Analytics ────────────────────────────────────────────────────────────

test.describe('UI: Analytics', () => {
  test.beforeEach(async ({ page, request }) => { await injectAuth(page, request); });

  // The days are the viewer's: the backend resolves an IANA zone on its
  // runtime image (time/tzdata is embedded; alpine has no zoneinfo).
  test('blocked-by-day returns the 7 calendar days of a zone, and coverage says what is on', async ({ request }) => {
    const token = await apiToken(request);
    const headers = { Authorization: `Bearer ${token}` };
    const res = await request.get(`${API_URL}/api/analytics/blocked-by-day?tz=Europe/Rome`, { headers });
    expect(res.ok(), await res.text()).toBeTruthy();
    const { data } = (await res.json()) as {
      data: { tz: string; days: { date: string; start: number; end: number; blocked: number; reasons: unknown[] }[]; reasons: unknown[] };
    };
    expect(data.tz).toBe('Europe/Rome');
    expect(data.days).toHaveLength(7);
    for (let i = 0; i < data.days.length; i++) {
      const d = data.days[i];
      expect(d.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(Array.isArray(d.reasons)).toBeTruthy();
      expect([23, 24, 25]).toContain((d.end - d.start) / 3600);
      if (i > 0) expect(d.start).toBe(data.days[i - 1].end);
    }
    const bad = await request.get(`${API_URL}/api/analytics/blocked-by-day?tz=Mars/Olympus`, { headers });
    expect(bad.status()).toBe(400);

    const cov = await request.get(`${API_URL}/api/analytics/coverage`, { headers });
    expect(cov.ok()).toBeTruthy();
    const c = ((await cov.json()) as { data: Record<string, unknown> }).data;
    expect(Object.keys(c).sort()).toEqual(['alerts', 'domain_blacklist', 'https_inspection', 'ip_blacklist', 'proxy_login', 'proxy_login_status', 'waf']);
    expect(['ok', 'auth_failed', 'unreachable', 'error']).toContain((c.waf as { status: string }).status);
    // The proxy's own record of proxy login: null until it has written one.
    const pls = c.proxy_login_status as { state: string } | null;
    if (pls !== null) expect(['off', 'enforced', 'no_credentials']).toContain(pls.state);
  });

  test('shows the sections of the mockup, and the old Threat Intel address leads here', async ({ page }) => {
    await page.goto('/threats');
    await expect(page).toHaveURL(/\/analytics$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Analytics' })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText('Last 7 days, client traffic only. Times are your local time.')).toBeVisible();
    await expect(page.getByRole('heading', { level: 2 })).toHaveText([
      'Blocked requests per day, by rule',
      'Protection coverage',
      'WAF categories',
      'Cloud services in use',
      'Traffic by kind of service',
      'Downloads by file type',
    ]);
    const perDay = page.getByRole('region', { name: 'Blocked requests per day, by rule' });
    await expect(
      perDay.getByRole('img', { name: /^Blocked requests per day, today and the 6 days before: / })
        .or(perDay.getByText('No blocked requests in the last 7 days')),
    ).toBeVisible();
    await expect(perDay.getByText(/midnight to midnight in your time zone \(.+\)\./)).toBeVisible();
    // Six coverage lines from analytics/coverage. The e2e stack has no proxy
    // and no WAF, so those say they did not report; what the backend reads
    // from its own database is always there.
    const coverage = page.getByRole('region', { name: 'Protection coverage' });
    await expect(coverage.getByRole('listitem')).toHaveCount(6);
    await expect(coverage.getByText(/^Domain blacklist: (empty|[\d,]+ entr)/)).toBeVisible();
    await expect(coverage.getByText(/^IP blacklist: (empty|[\d,]+ entr)/)).toBeVisible();
    await expect(coverage.getByText(/^WAF: ([\d,]+ |did not answer|refuses|answered|every)/)).toBeVisible();
    await expect(coverage.getByText(/^(HTTPS inspection|Proxy login): (on|off),/)).toHaveCount(2);
    await expect(coverage.getByText(/could not (count|read)/)).toHaveCount(0);
    for (const gone of ['Top Blocked', 'Live Feed', 'Top Domains', 'Regex Playground', 'Shadow IT']) {
      await expect(page.getByText(gone, { exact: true })).toHaveCount(0);
    }
    await expect(page.getByRole('link', { name: 'Every request: Access logs' })).toHaveAttribute('href', '/logs');
  });

  test('fits a 390 px wide screen without horizontal scrolling', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/analytics');
    await expect(page.getByRole('heading', { level: 1, name: 'Analytics' })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('region', { name: 'Protection coverage' }).getByRole('listitem')).toHaveCount(6);
    await expect(page.getByRole('region', { name: 'Downloads by file type' })).toBeVisible();
    const overflow = await page.evaluate(() => {
      const main = document.querySelector('main')!;
      return { doc: document.documentElement.scrollWidth - window.innerWidth, main: main.scrollWidth - main.clientWidth };
    });
    expect(overflow).toEqual({ doc: 0, main: 0 });
  });
});

// ─── UI: Egress allowlist ─────────────────────────────────────────────────────

test.describe('UI: Egress allowlist', () => {
  test.beforeEach(async ({ page, request }) => {
    await injectAuth(page, request);
    await page.goto('/egress');
    await expect(page.getByRole('heading', { level: 1, name: 'Egress allowlist' })).toBeVisible({ timeout: 15_000 });
  });

  test('says what the list does from the stored setting, and links to Filtering', async ({ page, request }) => {
    const token = await apiToken(request);
    const res = await request.get(`${API_URL}/api/settings`, { headers: { Authorization: `Bearer ${token}` } });
    const rows = ((await res.json()) as { data: { setting_name: string; setting_value: string }[] }).data;
    const on = rows.find((r) => r.setting_name === 'egress_default_deny')?.setting_value === 'true';
    const title = on ? /^Default deny is on/ : /^Default deny is off, so this list has no effect$/;
    const notice = page.getByRole('status').filter({ has: page.getByText(title) });
    await expect(notice).toBeVisible({ timeout: 10_000 });
    await expect(notice.getByRole('link', { name: 'Open Filtering' })).toHaveAttribute('href', '/settings/filtering');
    await expect(page.getByText(/A domain allows that exact name only: example\.com does not cover www\.example\.com\./)).toBeVisible();
  });

  test('a destination of the wrong kind is refused at its field before anything is sent', async ({ page }) => {
    let posted = false;
    page.on('request', (r) => { if (r.url().endsWith('/api/egress-allowlist') && r.method() === 'POST') posted = true; });
    await page.getByLabel('Destination', { exact: true }).fill('203.0.113.9');
    await page.getByRole('button', { name: 'Add', exact: true }).click();
    await expect(page.getByText('This is an address: choose IP or network as the kind.')).toBeVisible();
    await expect(page.getByLabel('Destination', { exact: true })).toHaveAttribute('aria-invalid', 'true');
    expect(posted).toBe(false);
  });

  test('add a destination, see the backend refuse it twice at the field, and remove it after a confirmation naming it', async ({ page }) => {
    // New on every attempt, so a retry does not meet its own leftover.
    const dest = `e2e-${Date.now().toString(36)}.example.org`;
    await page.getByLabel('Destination', { exact: true }).fill(dest);
    await page.getByLabel('Note (optional)', { exact: true }).fill('playwright');
    const [added] = await Promise.all([
      page.waitForResponse(r => r.url().endsWith('/api/egress-allowlist') && r.request().method() === 'POST', { timeout: 15_000 }),
      page.getByRole('button', { name: 'Add', exact: true }).click(),
    ]);
    expect(added.status()).toBe(200);
    await page.getByRole('searchbox', { name: 'Search the egress allowlist' }).fill(dest);
    const row = page.getByRole('table', { name: 'Allowed destinations' }).getByRole('row').filter({ has: page.getByText(dest, { exact: true }) });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await expect(row.getByText('Exact domain')).toBeVisible();
    await expect(row.getByText('playwright')).toBeVisible();

    // The same destination again: the backend's refusal is shown at the field.
    await page.getByLabel('Destination', { exact: true }).fill(dest);
    await page.getByRole('button', { name: 'Add', exact: true }).click();
    await expect(page.getByText('entry already in allowlist')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByLabel('Destination', { exact: true })).toHaveAttribute('aria-invalid', 'true');

    await row.getByRole('button', { name: `Remove ${dest}` }).click();
    await expect(page.getByRole('alertdialog').getByText(`Remove ${dest}?`)).toBeVisible();
    expect(await confirmDelete(page, 'Remove', '/api/egress-allowlist/')).toBe(200);
    await expect(page.getByText(`No destination matches "${dest}"`)).toBeVisible({ timeout: 10_000 });

    // Both changes are in the audit log, in words.
    await page.goto('/audit');
    await page.getByRole('group', { name: 'Show' }).getByRole('button', { name: 'Changes' }).click();
    const events = page.getByRole('table', { name: 'Audit events' });
    await expect(events.getByText(`Added ${dest} to the egress allowlist`)).toBeVisible({ timeout: 10_000 });
    await expect(events.getByText(`Removed ${dest} from the egress allowlist`)).toBeVisible();
  });

  test('fits a 390 px wide screen without horizontal scrolling', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/egress');
    await expect(page.getByRole('heading', { level: 1, name: 'Egress allowlist' })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('table', { name: 'Allowed destinations' })).toBeAttached();
    const overflow = await page.evaluate(() => {
      const main = document.querySelector('main')!;
      return { doc: document.documentElement.scrollWidth - window.innerWidth, main: main.scrollWidth - main.clientWidth };
    });
    expect(overflow).toEqual({ doc: 0, main: 0 });
  });
});

// ─── UI: Audit log ────────────────────────────────────────────────────────────

test.describe('UI: Audit log', () => {
  test.beforeEach(async ({ page, request }) => { await injectAuth(page, request); });

  // On a test deployment 640,929 domains were cleared and 71,140 imported,
  // and the audit log recorded neither.
  test('a list import and the removal of its source are audited with their counts, and shown in words', async ({ page, request }) => {
    const token = await apiToken(request);
    const headers = { Authorization: `Bearer ${token}` };
    const stamp = Date.now().toString(36);
    const domains = [`a-${stamp}.audit.test`, `b-${stamp}.audit.test`];
    const imp = await request.post(`${API_URL}/api/blacklists/import`, { headers, data: { type: 'domain', content: domains.join('\n') } });
    expect(imp.ok(), await imp.text()).toBeTruthy();

    const log = await request.get(`${API_URL}/api/audit-log?category=changes&limit=20`, { headers });
    expect(log.ok()).toBeTruthy();
    const body = (await log.json()) as { data: { action: string; details: string | null }[]; meta: { retention_days: number } };
    expect(body.meta.retention_days).toBe(365);
    const row = body.data.find((r) => r.action === 'import_domain_blacklist');
    expect(row, 'an import_domain_blacklist row').toBeTruthy();
    expect(JSON.parse(row!.details ?? '{}')).toMatchObject({ added: 2, from: 'paste' });
    expect(body.data.every((r) => !['login', 'login_failed', 'logout'].includes(r.action))).toBe(true);
    expect((await request.get(`${API_URL}/api/audit-log?category=bogus`, { headers })).status()).toBe(400);

    // The pasted list is one source: remove it, and the removal is counted.
    const sources = await request.get(`${API_URL}/api/domain-blacklist/sources`, { headers });
    const paste = ((await sources.json()) as { data: { id: number | null; kind: string; entries: number; last_added: string }[] }).data
      .find((s) => s.kind === 'paste' && s.entries === 2);
    expect(paste?.id, 'the pasted source').toBeTruthy();
    expect((await request.delete(`${API_URL}/api/domain-blacklist/sources/${paste!.id}`, { headers })).ok()).toBeTruthy();

    await page.goto('/audit');
    await expect(page.getByRole('heading', { level: 1, name: 'Audit log' })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText('Who changed what, and every sign-in. Kept for 365 days.')).toBeVisible();
    const events = page.getByRole('table', { name: 'Audit events' });
    await expect(events.getByText('Removed 2 blocked domains from a pasted list').first()).toBeVisible({ timeout: 10_000 });
    await expect(events.getByText('Added 2 domains to Blocked domains from a pasted list').first()).toBeVisible();
  });

  test('Sign-ins shows the session events only, filtered by the backend', async ({ page }) => {
    await page.goto('/audit');
    await expect(page.getByRole('heading', { level: 1, name: 'Audit log' })).toBeVisible({ timeout: 15_000 });
    const [resp] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/api/audit-log') && r.url().includes('category=signins'), { timeout: 15_000 }),
      page.getByRole('group', { name: 'Show' }).getByRole('button', { name: 'Sign-ins' }).click(),
    ]);
    expect(resp.status()).toBe(200);
    const events = page.getByRole('table', { name: 'Audit events' });
    // This run has signed in many times.
    await expect(events.getByText('Signed in').first()).toBeVisible({ timeout: 10_000 });
    const texts = await events.locator('tbody tr td:nth-child(3)').allInnerTexts();
    expect(texts.length).toBeGreaterThan(0);
    for (const t of texts) expect(['Signed in', 'Signed out', 'Sign-in failed']).toContain(t.trim());
    await expect(page.getByRole('button', { name: 'Newer' })).toBeDisabled();
  });

  test('fits a 390 px wide screen without horizontal scrolling', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/audit');
    await expect(page.getByRole('heading', { level: 1, name: 'Audit log' })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('table', { name: 'Audit events' })).toBeAttached();
    const overflow = await page.evaluate(() => {
      const main = document.querySelector('main')!;
      return { doc: document.documentElement.scrollWidth - window.innerWidth, main: main.scrollWidth - main.clientWidth };
    });
    expect(overflow).toEqual({ doc: 0, main: 0 });
  });
});

// ─── UI — Navigation ─────────────────────────────────────────────────────────

test.describe('UI — Navigation', () => {
  test.beforeEach(async ({ page, request }) => { await injectAuth(page, request); });

  test('navigates to /blacklists', async ({ page }) => {
    await page.goto('/blacklists');
    await expect(page.getByRole('tab', { name: /^Blocked IPs/ })).toBeVisible({ timeout: 15_000 });
  });

  test('navigates to /logs', async ({ page }) => {
    await page.goto('/logs');
    await expect(page.locator('body')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });

  test('navigates to /settings', async ({ page }) => {
    await page.goto('/settings');
    await expect(page.locator('body')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });

  test('unknown route shows 404', async ({ page }) => {
    await page.goto('/this-does-not-exist');
    await expect(page.getByText('404')).toBeVisible({ timeout: 10_000 });
  });
});

// ─── UI — Blacklists: Blocked IPs ─────────────────────────────────────────────

/** Open Add entries, on a method other than the first when named. */
async function openAdd(page: Page, method?: string): Promise<void> {
  await page.getByRole('button', { name: 'Add entries', exact: true }).click();
  if (method) await page.getByRole('group', { name: 'How to add' }).getByRole('button', { name: method }).click();
}

/** The row of the entries table that shows value, after searching for it. */
async function findEntry(page: Page, value: string) {
  await page.getByRole('searchbox', { name: /^Search / }).fill(value);
  const table = page.getByRole('table', { name: / entries$/ });
  const row = table.getByRole('row').filter({ has: page.getByText(value, { exact: true }) });
  await expect(row).toBeVisible({ timeout: 10_000 });
  return row;
}

/** Confirm the open dialog with the named button and wait for the DELETE it sends. */
async function confirmDelete(page: Page, button: string | RegExp, urlPart: string): Promise<number> {
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toBeVisible();
  const [resp] = await Promise.all([
    page.waitForResponse(r => r.url().includes(urlPart) && r.request().method() === 'DELETE', { timeout: 15_000 }),
    dialog.getByRole('button', { name: button }).click(),
  ]);
  return resp.status();
}

test.describe('UI — Blacklists (Blocked IPs)', () => {
  test.beforeEach(async ({ page, request }) => {
    await injectAuth(page, request);
    await page.goto('/blacklists');
    await expect(page.getByRole('heading', { level: 1, name: 'Blacklists' })).toBeVisible({ timeout: 15_000 });
  });

  test('Blocked IPs is the default tab and shows the actions and sections from the mockup', async ({ page }) => {
    await expect(page.getByRole('tab', { name: /^Blocked IPs/ })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('button', { name: 'Add entries', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Export' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Popular lists' })).toBeVisible();
    for (const h of ['Enforcement', 'Where the entries came from', 'Entries', 'Remove every entry on this list']) {
      await expect(page.getByRole('heading', { level: 2, name: h, exact: true })).toBeVisible();
    }
    // This stack runs no proxy, so its record of the merged networks is missing,
    // and the page says so instead of a number.
    await expect(page.getByText('Not reported: the proxy has not written ip_blacklist_acl_status.json')).toBeVisible();
  });

  test('Add a single IP: it is listed as Manual, and removed after a confirmation naming it', async ({ page }) => {
    const testIp = '192.0.2.55';
    await openAdd(page);
    await page.getByLabel('IP address or network').fill(testIp);
    const [resp] = await Promise.all([
      page.waitForResponse(r => r.url().endsWith('/api/ip-blacklist') && r.request().method() === 'POST', { timeout: 15_000 }),
      page.getByRole('button', { name: 'Add entry' }).click(),
    ]);
    expect([200, 400]).toContain(resp.status()); // 400 = duplicate on retry
    const row = await findEntry(page, testIp);
    await expect(row.getByText('Manual')).toBeVisible();
    await expect(row.getByText('IP', { exact: true })).toBeVisible();

    await row.getByRole('button', { name: `Remove ${testIp}` }).click();
    await expect(page.getByRole('alertdialog').getByText(`Remove ${testIp}?`)).toBeVisible();
    expect(await confirmDelete(page, 'Remove', '/api/ip-blacklist/')).toBe(200);
    await expect(page.getByText(`No entry matches "${testIp}"`)).toBeVisible({ timeout: 10_000 });
  });

  test('Paste a list: the paste is one source, removed as a whole with a confirmation naming the count', async ({ page }) => {
    // Addresses no other test uses, new on every attempt, so a retry adds
    // them again instead of skipping them as already listed.
    const base = 100 + Math.floor(Math.random() * 30) * 3;
    const ips = [0, 1, 2].map((i) => `198.51.100.${base + i}`);
    await openAdd(page, 'Paste a list');
    await page.getByLabel('Entries, one per line').fill([...ips, '# comment'].join('\n'));
    await page.getByRole('button', { name: 'Add pasted entries' }).click();
    await expect(page.getByText(/^Added 3 entries/)).toBeVisible({ timeout: 15_000 });

    const row = await findEntry(page, ips[0]);
    await expect(row.getByText('Pasted list')).toBeVisible();

    // Sources are listed most recently added first: this paste is the top
    // row, and its button names it with the time it was pasted.
    const sources = page.getByRole('table', { name: 'Sources of Blocked IPs' });
    const remove = sources.getByRole('button', { name: /^Remove batch: Pasted list, 3 entries, pasted \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/ }).first();
    await expect(remove).toBeVisible({ timeout: 10_000 });
    await remove.click();
    await expect(page.getByRole('alertdialog').getByText('Remove 3 entries from Pasted list?')).toBeVisible();
    expect(await confirmDelete(page, 'Remove 3 entries', '/api/ip-blacklist/sources/')).toBe(200);
    for (const ip of ips) {
      await page.getByRole('searchbox', { name: /^Search / }).fill(ip);
      await expect(page.getByText(`No entry matches "${ip}"`)).toBeVisible({ timeout: 10_000 });
    }
  });

  test('Import from URL: a private address is refused, and the panel says why', async ({ page }) => {
    await openAdd(page, 'Import from URL');
    const urlInput = page.getByLabel('List URL');
    await urlInput.fill(`${MOCK_URL}/ip-list.txt`);
    await expect(urlInput).toHaveValue(`${MOCK_URL}/ip-list.txt`);
    const [resp] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/api/blacklists/import') && r.request().method() === 'POST', { timeout: 30_000 }),
      page.getByRole('button', { name: 'Import list' }).click(),
    ]);
    // mock-lists is on the Docker network: the SSRF guard refuses it.
    expect(resp.status()).toBe(403);
    await expect(page.getByRole('alert').filter({ hasText: 'requests to private/reserved networks are blocked' })).toBeVisible();
  });

  test('Geo-block form opens and accepts a country code', async ({ page }) => {
    await openAdd(page, 'Geo-block');
    const countryInput = page.getByLabel('Country codes');
    await countryInput.fill('CN');
    await expect(countryInput).toHaveValue('CN');
    // The feed may or may not be reachable from CI; no crash is the assertion.
    await page.getByRole('button', { name: 'Download and block IPs' }).click();
    await page.waitForTimeout(5_000);
    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });

  test('keeps Remove batch inside its card at 1440 px, with a long URL source among them', async ({ page, request }) => {
    // Finding 29: a long URL widened the source column and pushed the button
    // 240 px past the card's right edge. This stack cannot import from a URL
    // (the SSRF guard refuses mock-lists), so the URL source is added to the
    // real answer of /sources.
    const token = await apiToken(request);
    await request.post(`${API_URL}/api/blacklists/import`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { type: 'ip', content: '203.0.113.211\n203.0.113.212' },
    });
    const longUrl = 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/a/very/long/path/to/the/list/firehol_level1.netset';
    await page.route('**/api/ip-blacklist/sources', async (route) => {
      const res = await route.fetch();
      const body = await res.json() as { data: unknown[] };
      body.data.unshift({
        id: 999999, kind: 'url', source: longUrl, label: '', entries: 50772,
        first_added: '2026-10-25 08:00:00', last_added: '2026-10-26 09:00:00',
      });
      await route.fulfill({ response: res, json: body });
    });
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.reload();
    const card = page.getByRole('region', { name: 'Where the entries came from' });
    const buttons = card.getByRole('button', { name: /^Remove batch:/ });
    await expect(buttons.first()).toBeVisible({ timeout: 15_000 });
    await expect(card.getByText(longUrl)).toHaveAttribute('title', longUrl);
    const box = (await card.boundingBox())!;
    const n = await buttons.count();
    expect(n).toBeGreaterThan(1);
    for (let i = 0; i < n; i++) {
      const b = (await buttons.nth(i).boundingBox())!;
      expect(b.x + b.width, `Remove batch ${i} ends inside the card`).toBeLessThanOrEqual(box.x + box.width);
    }
    const table = card.getByRole('table', { name: 'Sources of Blocked IPs' });
    expect(await table.evaluate((el) => (el.parentElement ?? el).scrollWidth - (el.parentElement ?? el).clientWidth)).toBe(0);
  });

  test('fits a 390 px wide screen without horizontal scrolling', async ({ page, request }) => {
    // With rows, both tables are wider than a phone and must scroll inside
    // their own boxes; an empty table would fit and prove nothing.
    const token = await apiToken(request);
    await request.post(`${API_URL}/api/blacklists/import`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { type: 'ip', content: '203.0.113.201\n203.0.113.202' },
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.reload();
    await expect(page.getByRole('heading', { level: 1, name: 'Blacklists' })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('table', { name: 'Blocked IPs entries' }).getByText('203.0.113.201')).toBeVisible();
    await expect(page.getByRole('table', { name: 'Sources of Blocked IPs' }).getByRole('button', { name: /^Remove batch:/ }).first()).toBeAttached();
    await page.getByRole('button', { name: 'Add entries', exact: true }).click();
    await page.getByRole('group', { name: 'How to add' }).getByRole('button', { name: 'Popular lists' }).click();
    const overflow = await page.evaluate(() => {
      const main = document.querySelector('main')!;
      return { doc: document.documentElement.scrollWidth - window.innerWidth, main: main.scrollWidth - main.clientWidth };
    });
    expect(overflow).toEqual({ doc: 0, main: 0 });
  });
});

// ─── UI — Blacklists: Blocked domains ─────────────────────────────────────────

test.describe('UI — Blacklists (Blocked domains)', () => {
  test.beforeEach(async ({ page, request }) => {
    await injectAuth(page, request);
    await page.goto('/blacklists?tab=blocked-domains');
    await expect(page.getByRole('tab', { name: /^Blocked domains/ })).toHaveAttribute('aria-selected', 'true', { timeout: 15_000 });
  });

  test('says what enforces the list, and how "*." entries match', async ({ page }) => {
    const enforcement = page.getByRole('region', { name: 'Enforcement' });
    await expect(enforcement.getByText('DNS sinkhole', { exact: true })).toBeVisible();
    await expect(enforcement.getByText('Set by SPM_DNS_BLOCKLIST_MAX_DOMAINS.')).toBeVisible();
    // This stack runs no proxy; a record left in ./config from another run
    // would say whether Squid holds a copy instead.
    await expect(enforcement.getByText(/^(Not reported: the proxy has not written domain_acl_status\.json|Its own copy of all|No copy:)/)).toBeVisible();
    await expect(enforcement.getByText(/"\*\.example\.com" and "\.example\.com" each block example\.com itself/)).toBeVisible();
  });

  test('add a domain, find it, remove it', async ({ page }) => {
    const testDomain = 'e2e-delete-me.test';
    await openAdd(page);
    await page.getByLabel('Domain', { exact: true }).fill(testDomain);
    const [resp] = await Promise.all([
      page.waitForResponse(r => r.url().endsWith('/api/domain-blacklist') && r.request().method() === 'POST', { timeout: 15_000 }),
      page.getByRole('button', { name: 'Add entry' }).click(),
    ]);
    expect([200, 400]).toContain(resp.status()); // 400 = duplicate on retry
    const row = await findEntry(page, testDomain);
    await expect(row.getByText('Domain', { exact: true })).toBeVisible();
    await row.getByRole('button', { name: `Remove ${testDomain}` }).click();
    expect(await confirmDelete(page, 'Remove', '/api/domain-blacklist/')).toBe(200);
  });

  test('a pasted list of domains is added', async ({ page }) => {
    await openAdd(page, 'Paste a list');
    await page.getByLabel('Entries, one per line').fill(['bulk-test-1.test', 'bulk-test-2.test', '# skip', 'bulk-test-3.test'].join('\n'));
    await page.getByRole('button', { name: 'Add pasted entries' }).click();
    // The toast, not a source's "Added <date>" line (shown on a phone only).
    await expect(page.getByText(/^Added \d+ entr/)).toBeVisible({ timeout: 15_000 });
  });

  test('the Blocked domains tab offers Block DNS-over-HTTPS, which used to sit in Settings', async ({ page }) => {
    await page.getByRole('tab', { name: /^Blocked domains/ }).click();
    await expect(page.getByRole('region', { name: 'Block DNS-over-HTTPS' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Block DoH resolvers' })).toBeVisible();
  });

  test('Popular lists opens from the header and shows the list names', async ({ page }) => {
    await page.getByRole('button', { name: 'Popular lists' }).click();
    for (const name of ['StevenBlack Unified', 'URLhaus Malware', 'Phishing Army']) {
      await expect(page.getByRole('button', { name: `Import ${name}` })).toBeVisible({ timeout: 10_000 });
    }
  });
});

// ─── UI — Blacklists: Allowed lists ───────────────────────────────────────────

test.describe('UI — Blacklists (Allowed lists)', () => {
  test.beforeEach(async ({ page, request }) => {
    await injectAuth(page, request);
    await page.goto('/blacklists');
    await expect(page.getByRole('tab', { name: /^Blocked IPs/ })).toBeVisible({ timeout: 15_000 });
  });

  test('a tab is in the URL, and Back returns to the one before', async ({ page }) => {
    await page.getByRole('tab', { name: /^Allowed IPs/ }).click();
    await expect(page).toHaveURL(/\/blacklists\?tab=allowed-ips$/);
    await expect(page.getByRole('tab', { name: /^Allowed IPs/ })).toHaveAttribute('aria-selected', 'true');
    await page.goBack();
    await expect(page.getByRole('tab', { name: /^Blocked IPs/ })).toHaveAttribute('aria-selected', 'true');
  });

  test('add an allowed network and see it listed as Manual', async ({ page }) => {
    const allowed = '10.88.88.0/28';
    await page.getByRole('tab', { name: /^Allowed IPs/ }).click();
    await openAdd(page);
    await page.getByLabel('IP address or network').fill(allowed);
    const [resp] = await Promise.all([
      page.waitForResponse(r => r.url().endsWith('/api/ip-whitelist') && r.request().method() === 'POST', { timeout: 15_000 }),
      page.getByRole('button', { name: 'Add entry' }).click(),
    ]);
    expect([200, 400]).toContain(resp.status()); // 400 = duplicate on retry
    const row = await findEntry(page, allowed);
    await expect(row.getByText('Manual')).toBeVisible();
    await expect(row.getByText('Network /28')).toBeVisible();
  });

  test('the Allowed domains tab offers the common services that used to sit in Settings', async ({ page }) => {
    await page.getByRole('tab', { name: /^Allowed domains/ }).click();
    await expect(page.getByRole('region', { name: 'Add common services' })).toBeVisible();
    await expect(page.getByRole('button', { name: '+ GitHub' })).toBeVisible();
  });

  test('an allowed list offers no URL import, Popular lists, Geo-block or Remove all', async ({ page }) => {
    await page.getByRole('tab', { name: /^Allowed domains/ }).click();
    await expect(page.getByRole('button', { name: 'Popular lists' })).not.toBeVisible();
    await expect(page.getByRole('heading', { name: 'Remove every entry on this list' })).not.toBeVisible();
    await openAdd(page);
    await expect(page.getByRole('group', { name: 'How to add' }).getByRole('button')).toHaveText(['Single entry', 'Paste a list']);
  });
});

// ─── UI — Logs page ───────────────────────────────────────────────────────────

test.describe('UI — Logs page', () => {
  test.beforeEach(async ({ page, request }) => {
    await injectAuth(page, request);
    await page.goto('/logs');
    await page.waitForTimeout(2_000);
  });

  test('page renders without crash', async ({ page }) => {
    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });

  test('shows log table or empty state', async ({ page }) => {
    const hasTable = await page.locator('table, [role="table"]').isVisible().catch(() => false);
    const hasEmpty = await page.getByText(/no logs|no results|empty/i).isVisible().catch(() => false);
    const hasLoader = await page.locator('[class*="spin"], [class*="load"]').isVisible().catch(() => false);
    expect(hasTable || hasEmpty || hasLoader).toBeTruthy();
  });

  test('search input is present', async ({ page }) => {
    // Logs page has: placeholder="Search by IP, domain, or status..."
    const input = page.locator('input[placeholder*="Search"], input[placeholder*="IP, domain"]').first();
    await expect(input).toBeVisible({ timeout: 10_000 });
  });
});

// ─── UI — Settings page ───────────────────────────────────────────────────────

test.describe('UI — Settings page', () => {
  test.beforeEach(async ({ page, request }) => {
    await injectAuth(page, request);
    await page.goto('/settings');
    await page.waitForTimeout(1_500);
  });

  test('/settings opens Overview and every section has its own URL', async ({ page }) => {
    await expect(page).toHaveURL(/\/settings\/overview$/);
    const nav = page.getByRole('navigation', { name: 'Settings sections' });
    await expect(nav.getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
    for (const [label, path] of [
      ['Clients and access', 'access'], ['Filtering', 'filtering'], ['Inspection', 'inspection'], ['Alerts', 'alerts'],
      ['Logs and privacy', 'logs'], ['Admin and backup', 'admin'], ['Proxy engine', 'engine'], ['Appearance', 'appearance'],
    ]) {
      await nav.getByRole('link', { name: label }).click();
      await expect(page).toHaveURL(new RegExp(`/settings/${path}$`));
      await expect(page.getByRole('heading', { level: 2, name: label })).toBeVisible();
      await expect(page.getByText('Something went wrong')).not.toBeVisible();
    }
    // The sidebar keeps Settings active on every section.
    await expect(page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Settings' })).toHaveAttribute('aria-current', 'page');
  });

  test('a deep link opens its section', async ({ page }) => {
    await page.goto('/settings/engine');
    await expect(page.getByRole('heading', { level: 2, name: 'Proxy engine' })).toBeVisible({ timeout: 10_000 });
    // Shown, not editable: compose and the health check pin it to 3128.
    await expect(page.getByTestId('proxy-port')).toHaveText('3128');
    await expect(page.locator('#proxy_port')).toHaveCount(0);
  });

  test('a section offers Save only once something changed, and Discard puts the stored value back', async ({ page }) => {
    await page.goto('/settings/logs');
    const retention = page.getByLabel('Keep logs for (days)');
    await expect(retention).toHaveValue(/^\d+$/, { timeout: 10_000 });
    const stored = await retention.inputValue();
    await expect(page.getByRole('button', { name: 'Save section' })).toHaveCount(0);
    await retention.fill(String(Number(stored) + 1));
    await expect(page.getByTestId('save-bar').getByRole('status')).toHaveText('1 unsaved change');
    await expect(page.getByRole('navigation', { name: 'Settings sections' }).getByRole('link', { name: /Logs and privacy, 1 unsaved change/ })).toBeVisible();
    await page.getByRole('button', { name: 'Discard' }).click();
    await expect(retention).toHaveValue(stored);
    await expect(page.getByRole('button', { name: 'Save section' })).toHaveCount(0);
  });

  test('saving a section says where the change takes effect', async ({ page }) => {
    await page.goto('/settings/logs');
    const retention = page.getByLabel('Keep logs for (days)');
    await expect(retention).toHaveValue(/^\d+$/, { timeout: 10_000 });
    const stored = await retention.inputValue();
    const changed = String(Number(stored) + 1);
    await retention.fill(changed);
    await page.getByRole('button', { name: 'Save section' }).click();
    const result = page.getByTestId('save-result');
    await expect(result).toContainText(/Saved at \d\d:\d\d\./);
    await expect(result).toContainText('Applied by the daily log cleanup.');
    // The backend has it: a reload of the page reads it back.
    await page.reload();
    await expect(page.getByLabel('Keep logs for (days)')).toHaveValue(changed, { timeout: 10_000 });
    // Put it back for the tests that follow.
    await page.getByLabel('Keep logs for (days)').fill(stored);
    await page.getByRole('button', { name: 'Save section' }).click();
    await expect(page.getByTestId('save-result')).toContainText(/Saved at/);
  });

  test('a save that needs the proxy reports what the proxy did', async ({ page }) => {
    // The test stack runs no proxy container, so nothing acknowledges the
    // reload: the page must say so instead of claiming it was applied.
    await page.goto('/settings/engine');
    const bypass = page.getByLabel('Never cache these domains');
    await expect(page.getByTestId('proxy-port')).toHaveText('3128', { timeout: 10_000 });
    const stored = await bypass.inputValue();
    await bypass.fill(stored ? `${stored}, e2e-bypass.test` : 'e2e-bypass.test');
    await page.getByRole('button', { name: 'Save section' }).click();
    const result = page.getByTestId('save-result');
    await expect(result).toContainText('Saved. The proxy did not confirm within 8 seconds: check that the proxy container is running.', { timeout: 20_000 });
    await expect(result).not.toContainText('Applied to the proxy');
    await expect(result.getByRole('button', { name: 'Apply again' })).toBeVisible();
    await bypass.fill(stored);
    await page.getByRole('button', { name: 'Save section' }).click();
    await expect(page.getByTestId('save-result')).toContainText('did not confirm', { timeout: 20_000 });
  });

  test('a value the proxy cannot use is named with its field, and nothing is saved', async ({ page }) => {
    await page.goto('/settings/engine');
    await expect(page.getByTestId('proxy-port')).toHaveText('3128', { timeout: 10_000 });
    await page.getByLabel('Memory cache (MB)').fill('1234567');
    await page.getByRole('button', { name: 'Save section' }).click();
    await expect(page.getByTestId('save-bar').getByRole('status')).toHaveText('Not saved: Memory cache (MB) needs attention');
    await expect(page.getByLabel('Memory cache (MB)')).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByText('Must be a whole number of megabytes, from 1 to 999999')).toBeVisible();
    await page.getByRole('button', { name: 'Discard' }).click();
  });

  test('Overview lists what needs attention from the running stack and previews a profile before applying it', async ({ page }) => {
    const attention = page.getByRole('region', { name: 'Needs attention' });
    // The test stack runs no proxy container: GET /api/status reports it.
    await expect(attention.getByText('The proxy is not running')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('navigation', { name: 'Settings sections' }).getByRole('link', { name: /^Overview, \d+ items? needs? attention$/ })).toBeVisible();
    await page.getByRole('button', { name: /^Family/ }).click();
    await expect(page.getByRole('heading', { level: 4, name: /^Family (changes \d+ settings?|already match)|Your settings already match Family/ })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Apply Family' })).toBeVisible();
    // Nothing is saved until Apply.
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('button', { name: 'Apply Family' })).toHaveCount(0);
  });

  test('Clients and access checks the time window before anything is sent', async ({ page }) => {
    await page.goto('/settings/access');
    await expect(page.getByRole('region', { name: 'Who may connect' })).toContainText('GUI_IP_WHITELIST');
    const hoursSwitch = page.getByRole('switch', { name: 'Limit to a time window' });
    await expect(hoursSwitch).toBeVisible({ timeout: 10_000 });
    if ((await hoursSwitch.getAttribute('aria-checked')) !== 'true') await hoursSwitch.click();
    await page.getByLabel('From').fill('18:00');
    await page.getByLabel('Until').fill('08:00');
    let posted = false;
    page.on('request', (r) => { if (r.method() === 'POST' && r.url().endsWith('/api/settings')) posted = true; });
    await page.getByRole('button', { name: 'Save section' }).click();
    await expect(page.getByLabel('Until')).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByText('Must be later than the start time')).toBeVisible();
    expect(posted).toBe(false);
    await page.getByRole('button', { name: 'Discard' }).click();
    await expect(page.getByRole('button', { name: 'Save section' })).toHaveCount(0);
  });

  test('Filtering shows the size of the egress allowlist it depends on', async ({ page }) => {
    await page.goto('/settings/filtering');
    await expect(page.getByText(/^The egress allowlist holds [\d,]+ (entry|entries)\.$/)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole('link', { name: 'Edit the allowlist' })).toHaveAttribute('href', '/egress');
  });

  for (const section of ['overview', 'access', 'filtering', 'inspection', 'alerts', 'logs', 'admin', 'engine', 'appearance']) {
    test(`/settings/${section} fits a 390 px wide screen without horizontal scrolling`, async ({ page }) => {
      await page.setViewportSize({ width: 390, height: 844 });
      await page.goto(`/settings/${section}`);
      const nav = page.getByRole('navigation', { name: 'Settings sections' });
      await expect(nav.getByRole('button', { name: /^Section: / })).toBeVisible({ timeout: 15_000 });
      await expect(page.getByRole('heading', { level: 2 }).first()).toBeVisible();
      const overflow = await page.evaluate(() => {
        const main = document.querySelector('main')!;
        return { doc: document.documentElement.scrollWidth - window.innerWidth, main: main.scrollWidth - main.clientWidth };
      });
      expect(overflow).toEqual({ doc: 0, main: 0 });
    });
  }

  test('Inspection tests a pattern against logged requests and shows the backend error for an invalid one', async ({ page }) => {
    // A request in the backend's access log (the tailer reads it every
    // 500 ms), in the proxy's logformat, timestamped now so it is in range.
    const logPath = process.env.SQUID_LOG_PATH ?? '/logs/access.log';
    const stamp = (Date.now() / 1000).toFixed(3);
    appendFileSync(logPath, `${stamp}      4 192.168.88.50 TCP_MISS/200 255 GET http://e2e-pattern.test/files/Sample.TORRENT - HIER_DIRECT/192.168.88.20 application/x-bittorrent - none -\n`);
    await page.goto('/settings/inspection');
    await expect(page.getByRole('heading', { level: 3, name: 'Test a pattern' })).toBeVisible({ timeout: 10_000 });
    const pattern = page.getByRole('textbox', { name: 'Pattern' });
    // Matched without regard to case, as the WAF compiles custom patterns.
    await expect(async () => {
      await pattern.fill('e2e-pattern\\.test/.*\\.torrent$');
      await page.getByRole('button', { name: 'Test', exact: true }).click();
      await expect(page.getByRole('list', { name: 'Matching URLs' })).toContainText('http://e2e-pattern.test/files/Sample.TORRENT', { timeout: 2_000 });
    }).toPass({ timeout: 20_000 });
    await expect(page.getByText(/^Matches \d+ of [\d,]+ requests? in the last 24 hours\.$/)).toBeVisible();
    // Go's regexp decides, and its message is shown.
    await pattern.fill('(unclosed');
    await page.getByRole('button', { name: 'Test', exact: true }).click();
    await expect(page.getByText('The pattern was not tested')).toBeVisible();
    await expect(page.getByText(/^invalid regex: error parsing regexp: missing closing \)/)).toBeVisible();
  });

  test('Alerts sends a test alert and says what happened', async ({ page }) => {
    await page.goto('/settings/alerts');
    await page.getByRole('button', { name: 'Send a test alert' }).click();
    // The test stack has no channel configured and no INTERNAL_ALERT_TOKEN.
    await expect(page.getByText('No alert channel has all of its settings stored: nothing was sent')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText('WAF block alerts do not arrive')).toBeVisible();
  });

  test('the sidebar has no theme control and Settings, Appearance switches the theme', async ({ page }) => {
    await expect(page.locator('#app-sidebar').getByRole('group', { name: 'Theme' })).toHaveCount(0);
    await expect(page.locator('#app-sidebar').getByRole('button', { name: /theme/i })).toHaveCount(0);
    await expect(page.locator('#app-sidebar img[src="/logo.svg"]')).toBeVisible();
    await page.goto('/settings/appearance');
    await page.getByRole('radio', { name: /^Dark/ }).check();
    await expect(page.locator('html')).toHaveClass(/(^|\s)dark(\s|$)/);
    await page.reload();
    await expect(page.getByRole('radio', { name: /^Dark/ })).toBeChecked({ timeout: 10_000 });
    await expect(page.locator('html')).toHaveClass(/(^|\s)dark(\s|$)/);
    await page.getByRole('radio', { name: /^Light/ }).check();
    await expect(page.locator('html')).not.toHaveClass(/(^|\s)dark(\s|$)/);
    await page.getByRole('radio', { name: /^System/ }).check();
  });

  test('Download a backup triggers a file download', async ({ page }) => {
    await page.goto('/settings/admin');
    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 15_000 }),
      page.getByRole('button', { name: 'Download a backup' }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/proxy-backup.*\.json/);
  });

  test('the button that empties the cache is visible', async ({ page }) => {
    await page.goto('/settings/admin');
    await expect(page.getByRole('button', { name: 'Empty disk and memory cache' })).toBeVisible({ timeout: 10_000 });
  });
});

// ─── UI — Error Boundary ──────────────────────────────────────────────────────

test.describe('UI — Error Boundary (all routes)', () => {
  test.beforeEach(async ({ page, request }) => { await injectAuth(page, request); });

  test('no crash on any route', async ({ page }) => {
    for (const path of ['/', '/blacklists', '/logs', '/settings']) {
      await page.goto(path);
      await page.waitForTimeout(500);
      await expect(page.getByText('Something went wrong')).not.toBeVisible();
    }
  });
});

// ─── Full onboarding scenario ─────────────────────────────────────────────────

test.describe('Full onboarding flow', () => {
  test('complete selfhoster workflow from login to backup', async ({ page }) => {
    // 1. Login via UI (page fixture starts with fresh sessionStorage — no need to clear)
    await page.goto('/');
    await expect(page.locator('h1', { hasText: 'Secure Proxy Manager' })).toBeVisible();
    await page.fill('#username', USERNAME);
    await page.fill('#password', PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page.getByRole('heading', { level: 1, name: 'Overview' }).first()).toBeVisible({ timeout: 15_000 });

    // 2. Note proxy address
    const proxyAddr = await page.locator('code').filter({ hasText: '3128' }).first().textContent();
    expect(proxyAddr).toMatch(/3128/);

    // 3. Block an IP
    await page.goto('/blacklists');
    await expect(page.getByRole('heading', { level: 1, name: 'Blacklists' })).toBeVisible({ timeout: 15_000 });
    await openAdd(page);
    await page.getByLabel('IP address or network').fill('192.0.2.200');
    const [ipResp] = await Promise.all([
      page.waitForResponse(r => r.url().endsWith('/api/ip-blacklist') && r.request().method() === 'POST', { timeout: 15_000 }),
      page.getByRole('button', { name: 'Add entry' }).click(),
    ]);
    expect([200, 201]).toContain(ipResp.status());

    // 4. Paste 3 domains
    await page.getByRole('tab', { name: /^Blocked domains/ }).click();
    await expect(page).toHaveURL(/tab=blocked-domains/);
    await page.getByRole('group', { name: 'How to add' }).getByRole('button', { name: 'Paste a list' }).click();
    await page.getByLabel('Entries, one per line').fill(['onboarding-1.test', 'onboarding-2.test', 'onboarding-3.test'].join('\n'));
    await page.getByRole('button', { name: 'Add pasted entries' }).click();
    await expect(page.getByText(/^Added \d+ (entry|entries)/)).toBeVisible({ timeout: 15_000 });

    // 5. Logs page — just confirm it loads
    await page.goto('/logs');
    await page.waitForTimeout(1_500);
    await expect(page.getByText('Something went wrong')).not.toBeVisible();

    // 6. Backup from settings
    await page.goto('/settings/admin');
    await page.waitForTimeout(1_000);
    const [dl] = await Promise.all([
      page.waitForEvent('download', { timeout: 15_000 }),
      page.getByRole('button', { name: 'Download a backup' }).click(),
    ]);
    expect(dl.suggestedFilename()).toMatch(/\.json$/);

    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });
});
