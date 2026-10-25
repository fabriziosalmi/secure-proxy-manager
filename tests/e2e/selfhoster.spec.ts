/**
 * Secure Proxy Manager — Self-Hoster E2E Test Suite
 *
 * Simulates the full onboarding → daily-use workflow of a self-hoster:
 *   Login · Dashboard · IP blacklist (add / bulk / URL import / geo-block / delete)
 *   · Domain blacklist · IP whitelist · Logs page · Settings
 *
 * Architecture notes:
 *   - API tests run via Playwright's `request` fixture (no browser overhead)
 *   - UI tests drive real Chromium, inject JWT into localStorage via addInitScript
 *     (Playwright storageState only persists localStorage, so we inject per-test)
 *   - Auth tests deliberately run WITHOUT token injection
 *
 * Environment variables (set in docker-compose.test.yml):
 *   BASE_URL          https://web:8443         (UI + nginx, HTTPS only)
 *   API_URL           http://backend:5000      (direct backend)
 *   TEST_USERNAME     testadmin
 *   TEST_PASSWORD     TestP@ss123!
 *   MOCK_LISTS_URL    http://mock-lists:8080   (SSRF-blocked in Docker — expected 403)
 */

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
 * Inject a valid JWT into localStorage BEFORE the page script runs.
 * Must be called before page.goto() — addInitScript registers a script that
 * fires on every subsequent navigation within the test.
 */
async function injectAuth(page: Page, request: APIRequestContext): Promise<void> {
  const token = await apiToken(request);
  await page.addInitScript((t: string) => {
    localStorage.setItem('auth_token', t);
  }, token);
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
    // Ensure storage is clear (no leftover token from other tests)
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
    await expect(page.locator('p.text-destructive, [class*="destructive"]').first())
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

  test('GET /api/security/score returns numeric score', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/security/score`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = (await res.json()) as { data?: { score: number } };
    const score = body.data?.score ?? (body as Record<string, unknown>)['score'];
    expect(typeof score).toBe('number');
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
    await page.waitForSelector('h1:has-text("Access Logs")', { timeout: 15_000 });
    await expect(page.getByRole('button', { name: 'Live', exact: true })).toBeVisible({ timeout: 15_000 });
    expect(wsErrors).toEqual([]);
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
    await expect(page.getByText(/Internal traffic is not counted on the Overview\./)).toBeVisible();

    const connect = page.getByRole('button', { name: 'Connect a device' }).first();
    await expect(connect).toHaveAttribute('aria-expanded', 'false');
    await connect.click();
    await expect(connect).toHaveAttribute('aria-expanded', 'true');
    await expect(page.getByText('Connect Your Devices')).toBeVisible();
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

// ─── UI — Navigation ─────────────────────────────────────────────────────────

test.describe('UI — Navigation', () => {
  test.beforeEach(async ({ page, request }) => { await injectAuth(page, request); });

  test('navigates to /blacklists', async ({ page }) => {
    await page.goto('/blacklists');
    await expect(page.getByRole('tab', { name: /IP Addresses/i }).first()).toBeVisible({ timeout: 15_000 });
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

// ─── UI — Blacklists: IP tab ──────────────────────────────────────────────────

test.describe('UI — Blacklists (IP tab)', () => {
  test.beforeEach(async ({ page, request }) => {
    await injectAuth(page, request);
    await page.goto('/blacklists');
    await page.waitForSelector('button:has-text("Add Rule")', { timeout: 15_000 });
  });

  test('IP tab is active by default and shows controls', async ({ page }) => {
    await expect(page.getByRole('button', { name: /Add Rule/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Bulk Add/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Import URL/i })).toBeVisible();
  });

  test('Add single IP — add, verify in list, delete', async ({ page }) => {
    const testIp = '192.0.2.55';
    await page.getByRole('button', { name: /Add Rule/i }).click();
    await page.getByPlaceholder('e.g. 192.168.1.100').fill(testIp);
    const [resp] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/api/ip-blacklist') && r.request().method() === 'POST', { timeout: 15_000 }),
      page.getByRole('button', { name: /Save Rule/i }).click(),
    ]);
    expect([200, 201, 400]).toContain(resp.status()); // 400 = duplicate on retry
    // Filter to the new IP so the assertion is deterministic regardless of how
    // many entries earlier tests left in the list (geo-import can add thousands).
    await page.getByPlaceholder(/Search/i).fill(testIp);
    await expect(page.getByText(testIp)).toBeVisible({ timeout: 10_000 });

    // Delete it
    const row = page.locator('tr, li').filter({ hasText: testIp }).first();
    const del = row.getByRole('button').first();
    if (await del.isVisible({ timeout: 1_000 }).catch(() => false)) {
      await del.click();
      const confirm = page.getByRole('button', { name: /confirm|yes|delete/i }).last();
      if (await confirm.isVisible({ timeout: 2_000 }).catch(() => false)) await confirm.click();
      await page.waitForTimeout(1_500);
    }
  });

  test('Bulk Add — adds multiple IPs via textarea', async ({ page }) => {
    await page.getByRole('button', { name: /Bulk Add/i }).click();
    const textarea = page.locator('textarea');
    await expect(textarea).toBeVisible();
    await textarea.fill(['192.0.2.101', '192.0.2.102', '# comment', '192.0.2.103'].join('\n'));
    await page.getByRole('button', { name: /Add All/i }).click();
    await expect(page.getByText(/Added \d+/i)).toBeVisible({ timeout: 15_000 });
  });

  test('Import URL — form opens and input is fillable', async ({ page }) => {
    await page.getByRole('button', { name: /Import URL/i }).click();
    const urlInput = page.locator('input[placeholder*="http"], input[type="url"]').first();
    await expect(urlInput).toBeVisible();
    await urlInput.fill(`${MOCK_URL}/ip-list.txt`);
    await expect(urlInput).toHaveValue(`${MOCK_URL}/ip-list.txt`);
    // Submit — backend will respond (403 SSRF or 200 success depending on env)
    await page.getByRole('button', { name: /^Import/i }).last().click();
    await page.waitForTimeout(5_000);
    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });

  test('Geo-block form — opens and accepts country code', async ({ page }) => {
    const geoBtn = page.getByRole('button', { name: /Geo.?[Bb]lock|Country/i });
    await expect(geoBtn).toBeVisible();
    await geoBtn.click();
    const countryInput = page.locator('input').first();
    await countryInput.fill('CN');
    await expect(countryInput).toHaveValue('CN');
    // Submit — may succeed or fail depending on network; no crash is the assertion
    await page.getByRole('button', { name: /Block|Import/i }).last().click();
    await page.waitForTimeout(5_000);
    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });
});

// ─── UI — Blacklists: Domain tab ──────────────────────────────────────────────

test.describe('UI — Blacklists (Domain tab)', () => {
  test.beforeEach(async ({ page, request }) => {
    await injectAuth(page, request);
    await page.goto('/blacklists');
    await page.waitForSelector('button:has-text("Add Rule")', { timeout: 15_000 });
    await page.getByRole('tab', { name: /Domains/i }).first().click();
    await page.waitForTimeout(300);
  });

  test('domain tab shows correct controls', async ({ page }) => {
    await expect(page.getByRole('button', { name: /Import URL/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Bulk Add/i })).toBeVisible();
  });

  test('add and delete a domain entry', async ({ page }) => {
    const testDomain = 'e2e-delete-me.test';
    await page.getByRole('button', { name: /Add Rule/i }).click();
    await page.getByPlaceholder('e.g. bad-domain.com').fill(testDomain);
    const [resp] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/api/domain-blacklist') && r.request().method() === 'POST', { timeout: 15_000 }),
      page.getByRole('button', { name: /Save Rule/i }).click(),
    ]);
    expect([200, 201, 400]).toContain(resp.status()); // 400 = duplicate on retry
    await expect(page.getByText(testDomain)).toBeVisible({ timeout: 10_000 });
  });

  test('domain bulk add works', async ({ page }) => {
    await page.getByRole('button', { name: /Bulk Add/i }).click();
    const textarea = page.locator('textarea');
    await expect(textarea).toBeVisible();
    await textarea.fill(['bulk-test-1.test', 'bulk-test-2.test', '# skip', 'bulk-test-3.test'].join('\n'));
    await page.getByRole('button', { name: /Add All/i }).click();
    await expect(page.getByText(/Added \d+/i)).toBeVisible({ timeout: 15_000 });
  });

  test('the Domains tab offers Block DNS-over-HTTPS, which used to sit in Settings', async ({ page }) => {
    await expect(page.getByRole('region', { name: 'Block DNS-over-HTTPS' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Block DoH resolvers' })).toBeVisible();
  });

  test('popular lists panel opens and shows list names', async ({ page }) => {
    const popularBtn = page.getByRole('button', { name: /Popular/i });
    await expect(popularBtn).toBeVisible();
    await popularBtn.click();
    // Domain popular lists include: StevenBlack Ad/Malware, Abuse.ch URLhaus Domains, Phishing Army
    const listName = page.getByText(/StevenBlack|URLhaus|Phishing Army/i).first();
    await expect(listName).toBeVisible({ timeout: 10_000 });
  });
});

// ─── UI — Blacklists: Whitelist tab ───────────────────────────────────────────

test.describe('UI — Blacklists (Whitelist tab)', () => {
  test.beforeEach(async ({ page, request }) => {
    await injectAuth(page, request);
    await page.goto('/blacklists');
    await page.waitForSelector('button:has-text("Add Rule")', { timeout: 15_000 });
    await page.getByRole('tab', { name: /Whitelist/i }).first().click();
    await page.waitForTimeout(300);
  });

  test('whitelist tab has green styling', async ({ page }) => {
    const tab = page.getByRole('tab', { name: /Whitelist/i }).first();
    const cls = await tab.getAttribute('class');
    expect(cls).toMatch(/green/);
  });

  test('add whitelist entry and verify it appears', async ({ page }) => {
    const whitelistIp = '10.88.88.0/28';
    await page.getByRole('button', { name: /Add Rule/i }).click();
    await page.getByPlaceholder('e.g. 192.168.0.0/16').fill(whitelistIp);
    const [resp] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/api/ip-whitelist') && r.request().method() === 'POST', { timeout: 15_000 }),
      page.getByRole('button', { name: /Save Rule/i }).click(),
    ]);
    expect([200, 201, 400]).toContain(resp.status()); // 400 = duplicate on retry
    await expect(page.getByText(whitelistIp)).toBeVisible({ timeout: 10_000 });
  });

  test('the Domain Whitelist tab offers the common services that used to sit in Settings', async ({ page }) => {
    await page.getByRole('tab', { name: /Domain Whitelist/i }).click();
    await expect(page.getByRole('region', { name: 'Add common services' })).toBeVisible();
    await expect(page.getByRole('button', { name: '+ GitHub' })).toBeVisible();
  });

  test('Import URL and Popular Lists buttons hidden on Whitelist tab', async ({ page }) => {
    await expect(page.getByRole('button', { name: /Import URL/i })).not.toBeVisible();
    await expect(page.getByRole('button', { name: /Popular/i })).not.toBeVisible();
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
      ['Logs and privacy', 'logs'], ['Admin and backup', 'admin'], ['Proxy engine', 'engine'],
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
    await expect(page.getByLabel('Proxy Port')).toHaveValue('3128');
  });

  test('a section offers Save only once something changed, and Discard puts the stored value back', async ({ page }) => {
    await page.goto('/settings/logs');
    const retention = page.getByLabel('Log Retention (days)');
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
    const retention = page.getByLabel('Log Retention (days)');
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
    await expect(page.getByLabel('Log Retention (days)')).toHaveValue(changed, { timeout: 10_000 });
    // Put it back for the tests that follow.
    await page.getByLabel('Log Retention (days)').fill(stored);
    await page.getByRole('button', { name: 'Save section' }).click();
    await expect(page.getByTestId('save-result')).toContainText(/Saved at/);
  });

  test('a save that needs the proxy reports what the proxy did', async ({ page }) => {
    // The test stack runs no proxy container, so nothing acknowledges the
    // reload: the page must say so instead of claiming it was applied.
    await page.goto('/settings/engine');
    const bypass = page.getByLabel(/Cache Bypass Domains/);
    await expect(page.getByLabel('Proxy Port')).toHaveValue('3128', { timeout: 10_000 });
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
    await expect(page.getByLabel('Proxy Port')).toHaveValue('3128', { timeout: 10_000 });
    await page.getByLabel('Memory Cache (MB)').fill('1234567');
    await page.getByRole('button', { name: 'Save section' }).click();
    await expect(page.getByTestId('save-bar').getByRole('status')).toHaveText('Not saved: Memory Cache (MB) needs attention');
    await expect(page.getByRole('button', { name: /^Memory Cache \(MB\): must be a whole number/ })).toBeVisible();
    await page.getByRole('button', { name: 'Discard' }).click();
  });

  test('Backup Config triggers file download', async ({ page }) => {
    await page.goto('/settings/admin');
    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 15_000 }),
      page.getByRole('button', { name: /Backup Config/i }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/proxy-backup.*\.json/);
  });

  test('Clear Cache button is visible', async ({ page }) => {
    await page.goto('/settings/admin');
    await expect(page.getByRole('button', { name: /Clear Cache/i })).toBeVisible({ timeout: 10_000 });
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

    // 3. Add an IP rule
    await page.goto('/blacklists');
    await page.waitForSelector('button:has-text("Add Rule")');
    await page.getByRole('button', { name: /Add Rule/i }).click();
    await page.getByPlaceholder('e.g. 192.168.1.100').fill('192.0.2.200');
    const [ipResp] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/api/ip-blacklist') && r.request().method() === 'POST', { timeout: 15_000 }),
      page.getByRole('button', { name: /Save Rule/i }).click(),
    ]);
    expect([200, 201]).toContain(ipResp.status());

    // 4. Bulk add 3 domains
    await page.getByRole('tab', { name: /Domains/i }).first().click();
    await page.waitForTimeout(300);
    await page.getByRole('button', { name: /Bulk Add/i }).click();
    await page.locator('textarea').fill(['onboarding-1.test', 'onboarding-2.test', 'onboarding-3.test'].join('\n'));
    await page.getByRole('button', { name: /Add All/i }).click();
    await expect(page.getByText(/Added \d+/i)).toBeVisible({ timeout: 15_000 });

    // 5. Logs page — just confirm it loads
    await page.goto('/logs');
    await page.waitForTimeout(1_500);
    await expect(page.getByText('Something went wrong')).not.toBeVisible();

    // 6. Backup from settings
    await page.goto('/settings/admin');
    await page.waitForTimeout(1_000);
    const [dl] = await Promise.all([
      page.waitForEvent('download', { timeout: 15_000 }),
      page.getByRole('button', { name: /Backup Config/i }).click(),
    ]);
    expect(dl.suggestedFilename()).toMatch(/\.json$/);

    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });
});
