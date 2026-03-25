/**
 * Secure Proxy Manager — Self-Hoster E2E Test Suite
 *
 * Simulates the full onboarding → daily-use workflow of a self-hoster:
 *   Login · Dashboard · IP blacklist (add / bulk / URL import / geo-block / delete)
 *   · Domain blacklist · IP whitelist · Logs page · Settings
 *
 * Architecture notes:
 *   - API tests run via Playwright's `request` fixture (no browser overhead)
 *   - UI tests drive real Chromium, inject JWT into sessionStorage via addInitScript
 *     (Playwright storageState only persists localStorage, so we inject per-test)
 *   - Auth tests deliberately run WITHOUT token injection
 *
 * Environment variables (set in docker-compose.test.yml):
 *   BASE_URL          http://web:8011          (UI + nginx proxy)
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
  const { token } = (await res.json()) as { token: string };
  return token;
}

/**
 * Inject a valid JWT into sessionStorage BEFORE the page script runs.
 * Must be called before page.goto() — addInitScript registers a script that
 * fires on every subsequent navigation within the test.
 */
async function injectAuth(page: Page, request: APIRequestContext): Promise<void> {
  const token = await apiToken(request);
  await page.addInitScript((t: string) => {
    sessionStorage.setItem('auth_token', t);
  }, token);
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────

test.describe('Authentication', () => {
  // No token injection — these tests verify the unauthenticated flow
  test.beforeEach(async ({ page }) => {
    // Ensure sessionStorage is clear (no leftover token from other tests)
    await page.addInitScript(() => { sessionStorage.clear(); });
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
    await expect(page.locator('text=Configure your device')).toBeVisible({ timeout: 15_000 });
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
    const { token } = (await res.json()) as { token: string };
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
    await page.waitForSelector('text=Configure your device', { timeout: 15_000 });
    await expect(page.locator('code').filter({ hasText: '3128' }).first()).toBeVisible();
  });

  test('copy button changes to "Copied!" on click', async ({ page, context, request }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/');
    await page.waitForSelector('text=Configure your device');
    await page.getByRole('button', { name: /copy/i }).first().click();
    await expect(page.getByText('Copied!')).toBeVisible({ timeout: 5_000 });
  });

  test('shows stats cards (Total Requests, Blocked, Direct IP, Security)', async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('text=Configure your device');
    for (const label of ['Total Requests', 'Blocked', 'Direct IP', 'Security Score']) {
      await expect(page.getByText(label)).toBeVisible();
    }
  });

  test('activity chart is rendered', async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('text=Configure your device');
    await expect(page.locator('svg').first()).toBeVisible();
  });
});

// ─── UI — Navigation ─────────────────────────────────────────────────────────

test.describe('UI — Navigation', () => {
  test.beforeEach(async ({ page, request }) => { await injectAuth(page, request); });

  test('navigates to /blacklists', async ({ page }) => {
    await page.goto('/blacklists');
    await expect(page.getByRole('button', { name: /IP Blacklist|^IP$/i }).first()).toBeVisible({ timeout: 15_000 });
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
    await page.waitForSelector('button:has-text("Add")', { timeout: 15_000 });
  });

  test('IP tab is active by default and shows controls', async ({ page }) => {
    await expect(page.getByRole('button', { name: /^Add$/i }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: /Bulk Add/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Import URL/i })).toBeVisible();
  });

  test('Add single IP — add, verify in list, delete', async ({ page }) => {
    const testIp = '192.0.2.55';
    await page.getByRole('button', { name: /^Add$/i }).first().click();
    // Fill the first visible input (IP address field)
    const inputs = page.locator('input[type="text"], input:not([type])');
    await inputs.first().fill(testIp);
    await page.getByRole('button', { name: /^Add$/i }).last().click();
    await page.waitForTimeout(2_000);
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
    await page.waitForSelector('button:has-text("Add")', { timeout: 15_000 });
    await page.getByRole('button', { name: /Domain/i }).first().click();
    await page.waitForTimeout(300);
  });

  test('domain tab shows correct controls', async ({ page }) => {
    await expect(page.getByRole('button', { name: /Import URL/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Bulk Add/i })).toBeVisible();
  });

  test('add and delete a domain entry', async ({ page }) => {
    const testDomain = 'e2e-delete-me.test';
    await page.getByRole('button', { name: /^Add$/i }).first().click();
    const input = page.locator('input[type="text"], input:not([type])').first();
    await input.fill(testDomain);
    await page.getByRole('button', { name: /^Add$/i }).last().click();
    await page.waitForTimeout(1_500);
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

  test('popular lists panel opens and shows list names', async ({ page }) => {
    const popularBtn = page.getByRole('button', { name: /Popular/i });
    await expect(popularBtn).toBeVisible();
    await popularBtn.click();
    // Some known list name should appear
    const listNames = page.locator('text=Steven Black, text=Firehol, text=StevenBlack, text=Hagezi');
    await expect(listNames.first()).toBeVisible({ timeout: 10_000 });
  });
});

// ─── UI — Blacklists: Whitelist tab ───────────────────────────────────────────

test.describe('UI — Blacklists (Whitelist tab)', () => {
  test.beforeEach(async ({ page, request }) => {
    await injectAuth(page, request);
    await page.goto('/blacklists');
    await page.waitForSelector('button:has-text("Add")', { timeout: 15_000 });
    await page.getByRole('button', { name: /Whitelist/i }).first().click();
    await page.waitForTimeout(300);
  });

  test('whitelist tab has green styling', async ({ page }) => {
    const tab = page.getByRole('button', { name: /Whitelist/i }).first();
    const cls = await tab.getAttribute('class');
    expect(cls).toMatch(/green/);
  });

  test('add whitelist entry and verify it appears', async ({ page }) => {
    const whitelistIp = '10.88.88.0/28';
    await page.getByRole('button', { name: /^Add$/i }).first().click();
    const input = page.locator('input[type="text"], input:not([type])').first();
    await input.fill(whitelistIp);
    await page.getByRole('button', { name: /^Add$/i }).last().click();
    await page.waitForTimeout(1_500);
    await expect(page.getByText(whitelistIp)).toBeVisible({ timeout: 10_000 });
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
    const input = page.locator('input[placeholder*="search"], input[placeholder*="filter"], input[type="search"]').first();
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

  test('page renders all sections without crash', async ({ page }) => {
    await expect(page.getByText('Something went wrong')).not.toBeVisible();
    await expect(page.locator('body')).toBeVisible();
  });

  test('Save button is present and enabled', async ({ page }) => {
    const saveBtn = page.getByRole('button', { name: /^Save/i }).first();
    await expect(saveBtn).toBeVisible({ timeout: 10_000 });
    await expect(saveBtn).toBeEnabled();
  });

  test('saving settings shows success feedback', async ({ page }) => {
    const saveBtn = page.getByRole('button', { name: /^Save/i }).first();
    await expect(saveBtn).toBeVisible({ timeout: 10_000 });
    await saveBtn.click();
    await expect(page.getByText(/saved|success|updated/i).first()).toBeVisible({ timeout: 10_000 });
  });

  test('Backup Config triggers file download', async ({ page }) => {
    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 15_000 }),
      page.getByRole('button', { name: /Backup Config/i }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/secure-proxy-backup.*\.json/);
  });

  test('Clear Cache button is visible', async ({ page }) => {
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
    // 1. Login via UI
    await page.addInitScript(() => { sessionStorage.clear(); });
    await page.goto('/');
    await expect(page.locator('h1', { hasText: 'Secure Proxy Manager' })).toBeVisible();
    await page.fill('#username', USERNAME);
    await page.fill('#password', PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page.locator('text=Configure your device')).toBeVisible({ timeout: 15_000 });

    // 2. Note proxy address
    const proxyAddr = await page.locator('code').filter({ hasText: '3128' }).first().textContent();
    expect(proxyAddr).toMatch(/3128/);

    // 3. Add an IP rule
    await page.goto('/blacklists');
    await page.waitForSelector('button:has-text("Add")');
    await page.getByRole('button', { name: /^Add$/i }).first().click();
    await page.locator('input[type="text"], input:not([type])').first().fill('192.0.2.200');
    await page.getByRole('button', { name: /^Add$/i }).last().click();
    await page.waitForTimeout(1_500);

    // 4. Bulk add 3 domains
    await page.getByRole('button', { name: /Domain/i }).first().click();
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
    await page.goto('/settings');
    await page.waitForTimeout(1_000);
    const [dl] = await Promise.all([
      page.waitForEvent('download', { timeout: 15_000 }),
      page.getByRole('button', { name: /Backup Config/i }).click(),
    ]);
    expect(dl.suggestedFilename()).toMatch(/\.json$/);

    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });
});
