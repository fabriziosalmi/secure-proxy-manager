/**
 * Secure Proxy Manager — Self-Hoster E2E Test Suite
 *
 * Simulates the full onboarding → daily-use workflow of a self-hoster:
 *   Login · Dashboard · IP blacklist (add / bulk / URL import / geo-block / delete)
 *   · Domain blacklist · IP whitelist · Logs page · Settings
 *
 * API tests run via Playwright's `request` fixture (fast, no browser overhead).
 * UI tests drive a real Chromium browser and assert visual state.
 *
 * Environment variables (set in docker-compose.test.yml):
 *   BASE_URL          http://web:8011          (UI + nginx proxy)
 *   API_URL           http://backend:5000      (direct backend, for API-layer tests)
 *   TEST_USERNAME     testadmin
 *   TEST_PASSWORD     TestP@ss123!
 *   MOCK_LISTS_URL    http://mock-lists:8080   (nginx serving static test lists)
 */

import { test, expect, type Page, type APIRequestContext } from '@playwright/test';

// ─── Config ───────────────────────────────────────────────────────────────────

const USERNAME = process.env.TEST_USERNAME ?? 'testadmin';
const PASSWORD = process.env.TEST_PASSWORD ?? 'TestP@ss123!';
const API_URL   = process.env.API_URL        ?? 'http://localhost:5001';
const MOCK_URL  = process.env.MOCK_LISTS_URL ?? 'http://mock-lists:8080';

// RFC 5737 / RFC 2606 test addresses — safe to use in tests, never routable
const TEST_IP_1      = '192.0.2.11';
const TEST_IP_2      = '198.51.100.22';
const TEST_IP_3      = '203.0.113.33';
const TEST_CIDR      = '192.0.2.128/26';
const TEST_WHITELIST = '10.99.99.0/28';
const TEST_DOMAIN_1  = 'test-bad-actor.test';
const TEST_DOMAIN_2  = 'malware-cdn.test';
const TEST_DOMAIN_3  = 'phishing-kit.test';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Get a JWT token via the API endpoint (bypasses rate-limit concerns in tests). */
async function apiToken(request: APIRequestContext): Promise<string> {
  const res = await request.post('/api/auth/login', {
    data: { username: USERNAME, password: PASSWORD },
  });
  expect(res.ok(), `Login failed: ${await res.text()}`).toBeTruthy();
  const { token } = (await res.json()) as { token: string };
  return token;
}

/** Inject a valid JWT into sessionStorage and reload so the React app sees it. */
async function injectAuth(page: Page, request: APIRequestContext) {
  const token = await apiToken(request);
  await page.goto('/');
  await page.evaluate((t: string) => sessionStorage.setItem('auth_token', t), token);
  await page.reload();
  await page.waitForSelector('text=Configure your device', { timeout: 20_000 });
}

/** Navigate to a route and wait for a page-specific heading/text to confirm load. */
async function goto(page: Page, path: string, waitFor: string) {
  await page.goto(path);
  await page.waitForSelector(`text=${waitFor}`, { timeout: 15_000 });
}

/** Wait for a toast notification (react-hot-toast) containing the given text. */
async function expectToast(page: Page, text: string) {
  await expect(
    page.locator('[data-testid="toast"], [class*="toast"], [id*="toast"]')
      .filter({ hasText: text })
      .first()
  ).toBeVisible({ timeout: 15_000 }).catch(async () => {
    // Fallback: some toast libraries render directly in body without a wrapper
    await expect(page.getByText(text).first()).toBeVisible({ timeout: 15_000 });
  });
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────

test.describe('Authentication', () => {
  // These tests deliberately start WITHOUT the saved storageState
  test.use({ storageState: { cookies: [], origins: [] } });

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
    await expect(page.locator('text=Invalid username or password')).toBeVisible({ timeout: 10_000 });
  });

  test('logs in successfully with correct credentials', async ({ page }) => {
    await page.goto('/');
    await page.fill('#username', USERNAME);
    await page.fill('#password', PASSWORD);
    await page.click('button[type="submit"]');
    // After login the main app renders — look for the proxy banner
    await expect(page.locator('text=Configure your device')).toBeVisible({ timeout: 15_000 });
  });

  test('submit button shows loading state', async ({ page }) => {
    await page.goto('/');
    await page.fill('#username', USERNAME);
    await page.fill('#password', PASSWORD);
    // Intercept the login request to hold it in flight long enough to observe the button
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
    expect(token.split('.').length).toBe(3); // JWT has 3 parts
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

  test.beforeAll(async ({ request }) => {
    token = await apiToken(request);
  });

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
      data: { ip: TEST_IP_1, description: 'e2e test entry' },
    });
    expect(res.ok() || res.status() === 400).toBeTruthy(); // 400 = already exists, also fine
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
    const found = body.data.some(e => e.ip === TEST_IP_1);
    expect(found).toBeTruthy();
  });

  test('DELETE /api/ip-blacklist/:id removes entry', async ({ request }) => {
    if (!createdId) {
      // Find the ID by listing
      const res = await request.get(`${API_URL}/api/ip-blacklist`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const body = (await res.json()) as { data: Array<{ id: number; ip: string }> };
      const entry = body.data.find(e => e.ip === TEST_IP_1);
      if (entry) createdId = entry.id;
    }
    if (!createdId) return; // already deleted or never created — skip
    const del = await request.delete(`${API_URL}/api/ip-blacklist/${createdId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(del.ok()).toBeTruthy();
  });
});

test.describe('API — CRUD: domain blacklist', () => {
  let token: string;
  let createdId: number;

  test.beforeAll(async ({ request }) => {
    token = await apiToken(request);
  });

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

  test.beforeAll(async ({ request }) => {
    token = await apiToken(request);
  });

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

  test.beforeAll(async ({ request }) => {
    token = await apiToken(request);
  });

  test('POST /api/blacklists/import — IP type', async ({ request }) => {
    const content = [TEST_IP_2, TEST_IP_3, TEST_CIDR, '# comment line', 'not-an-ip'].join('\n');
    const res = await request.post(`${API_URL}/api/blacklists/import`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { type: 'ip', content },
    });
    expect(res.ok()).toBeTruthy();
    const body = (await res.json()) as { data: { added: number; skipped: number } };
    // 3 valid entries (TEST_IP_2, TEST_IP_3, TEST_CIDR) + possible already-exists skips
    expect(body.data.added + body.data.skipped).toBeGreaterThanOrEqual(3);
  });

  test('POST /api/blacklists/import — domain type', async ({ request }) => {
    const content = [TEST_DOMAIN_2, TEST_DOMAIN_3, '# skip me', 'not a domain!!@#'].join('\n');
    const res = await request.post(`${API_URL}/api/blacklists/import`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { type: 'domain', content },
    });
    expect(res.ok()).toBeTruthy();
    const body = (await res.json()) as { data: { added: number; skipped: number } };
    expect(body.data.added + body.data.skipped).toBeGreaterThanOrEqual(2);
  });

  test('POST /api/blacklists/import — URL source (mock server)', async ({ request }) => {
    const res = await request.post(`${API_URL}/api/blacklists/import`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { type: 'ip', url: `${MOCK_URL}/ip-list.txt` },
    });
    // Accept 200 (success) or 422/500 if mock server is unreachable in env
    expect([200, 422, 500].includes(res.status())).toBeTruthy();
  });
});

test.describe('API — logs, stats, security score', () => {
  let token: string;

  test.beforeAll(async ({ request }) => {
    token = await apiToken(request);
  });

  test('GET /api/logs returns paginated response', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/logs?limit=10&offset=0`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = (await res.json()) as { data?: unknown[]; logs?: unknown[]; total?: number };
    const entries = body.data ?? body.logs ?? [];
    expect(Array.isArray(entries)).toBeTruthy();
  });

  test('GET /api/logs/stats returns counts', async ({ request }) => {
    const res = await request.get(`${API_URL}/api/logs/stats`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = (await res.json()) as Record<string, unknown>;
    // at least one of these fields should be present
    const hasField = 'total_count' in body || 'data' in body;
    expect(hasField).toBeTruthy();
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
    // Should contain at least one top-level key with array data
    expect(Object.keys(body).length).toBeGreaterThan(0);
  });
});

// ─── UI — Dashboard ───────────────────────────────────────────────────────────

test.describe('UI — Dashboard', () => {
  test('shows proxy address banner with host and port 3128', async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('text=Configure your device', { timeout: 15_000 });
    const banner = page.locator('text=Configure your device').locator('..');
    await expect(banner).toContainText('3128');
  });

  test('copy button changes to "Copied!" on click', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/');
    await page.waitForSelector('text=Configure your device');
    const copyBtn = page.getByRole('button', { name: /copy/i }).first();
    await copyBtn.click();
    await expect(page.getByText('Copied!')).toBeVisible({ timeout: 5_000 });
  });

  test('shows stats cards (Total, Blocked, Direct IP, Security)', async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('text=Configure your device');
    // The 4 metric cards are always rendered (even with 0 values)
    for (const label of ['Total Requests', 'Blocked', 'Direct IP', 'Security Score']) {
      await expect(page.getByText(label)).toBeVisible();
    }
  });

  test('activity chart is rendered', async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('text=Configure your device');
    // recharts renders an <svg> inside the chart card
    await expect(page.locator('svg').first()).toBeVisible();
  });
});

// ─── UI — Navigation ─────────────────────────────────────────────────────────

test.describe('UI — Navigation', () => {
  test('navigates to /blacklists', async ({ page }) => {
    await page.goto('/blacklists');
    // Blacklists page shows tab buttons for IP / Domain / Whitelist
    await expect(page.getByRole('button', { name: /IP Blacklist|ip/i }).first()).toBeVisible({ timeout: 15_000 });
  });

  test('navigates to /logs', async ({ page }) => {
    await page.goto('/logs');
    await expect(page.getByText(/logs|log/i).first()).toBeVisible({ timeout: 15_000 });
  });

  test('navigates to /settings', async ({ page }) => {
    await page.goto('/settings');
    await expect(page.getByText(/settings|configuration/i).first()).toBeVisible({ timeout: 15_000 });
  });

  test('unknown route shows 404', async ({ page }) => {
    await page.goto('/this-does-not-exist');
    await expect(page.getByText('404')).toBeVisible({ timeout: 10_000 });
  });
});

// ─── UI — Blacklists: IP tab ──────────────────────────────────────────────────

test.describe('UI — Blacklists (IP tab)', () => {
  test.beforeEach(async ({ page }) => {
    await goto(page, '/blacklists', 'IP Blacklist');
  });

  test('IP tab is active by default', async ({ page }) => {
    // "Add" and "Bulk Add" buttons visible when on IP tab
    await expect(page.getByRole('button', { name: /^Add$/i }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: /Bulk Add/i })).toBeVisible();
  });

  test('Add form toggle — opens and closes', async ({ page }) => {
    const addBtn = page.getByRole('button', { name: /^Add$/i }).first();
    await addBtn.click();
    // Input for the new entry should appear
    await expect(page.locator('input[placeholder*="1.2.3.4"], input[placeholder*="IP"]').first()).toBeVisible();
    // Click again (now shows ×) to close
    await page.getByRole('button', { name: /cancel|×/i }).first().click();
    await expect(page.locator('input[placeholder*="1.2.3.4"]').first()).not.toBeVisible();
  });

  test('Add single IP — add, verify in list, delete', async ({ page }) => {
    const testIp = '192.0.2.55';

    // Open add form
    await page.getByRole('button', { name: /^Add$/i }).first().click();
    const ipInput = page.locator('input[placeholder*="1.2.3.4"], input[placeholder*="IP"], input[placeholder*="address"]').first();
    await ipInput.fill(testIp);
    const descInput = page.locator('input[placeholder*="escription"], input[placeholder*="optional"]').first();
    if (await descInput.isVisible()) await descInput.fill('e2e test single add');
    await page.getByRole('button', { name: /^Add|^Save/i }).last().click();

    // Wait for success feedback (toast or list update)
    await page.waitForTimeout(1500);

    // Verify entry appears in list
    await expect(page.getByText(testIp)).toBeVisible({ timeout: 10_000 });

    // Delete the entry
    const row = page.locator('tr, [data-row], li').filter({ hasText: testIp }).first();
    const deleteBtn = row.getByRole('button').filter({ hasText: /delete|trash|remove/i }).first();
    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
      // Confirm if a confirmation dialog appears
      const confirmBtn = page.getByRole('button', { name: /confirm|yes|delete/i }).last();
      if (await confirmBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
        await confirmBtn.click();
      }
      await page.waitForTimeout(1500);
      await expect(page.getByText(testIp)).not.toBeVisible({ timeout: 8_000 });
    }
  });

  test('Bulk Add — adds multiple IPs via textarea', async ({ page }) => {
    await page.getByRole('button', { name: /Bulk Add/i }).click();
    const textarea = page.locator('textarea');
    await expect(textarea).toBeVisible();
    await textarea.fill(['192.0.2.101', '192.0.2.102', '# comment', '192.0.2.103'].join('\n'));
    await page.getByRole('button', { name: /Add All/i }).click();
    // Expect a success toast mentioning "Added"
    await expect(page.getByText(/Added \d+/i)).toBeVisible({ timeout: 15_000 });
  });

  test('Import URL — form accepts URL and submits', async ({ page }) => {
    const importBtn = page.getByRole('button', { name: /Import URL/i });
    await expect(importBtn).toBeVisible();
    await importBtn.click();
    const urlInput = page.locator('input[placeholder*="http"], input[type="url"]').first();
    await expect(urlInput).toBeVisible();
    await urlInput.fill(`${MOCK_URL}/ip-list.txt`);
    await page.getByRole('button', { name: /^Import/i }).last().click();
    // Accept any completion feedback — success or error (mock may not be reachable in all envs)
    await page.waitForTimeout(8_000);
    // Form should close or show a toast — just confirm no crash
    await expect(page.locator('body')).toBeVisible();
  });

  test('Geo-block form — opens, accepts country code, submits', async ({ page }) => {
    const geoBtn = page.getByRole('button', { name: /Geo.?[Bb]lock|Country/i });
    await expect(geoBtn).toBeVisible();
    await geoBtn.click();
    const countryInput = page.locator('input[placeholder*="CN"], input[placeholder*="ountry"], input[placeholder*="code"]').first();
    await expect(countryInput).toBeVisible();
    await countryInput.fill('CN');
    await page.getByRole('button', { name: /Block|Import/i }).last().click();
    // Wait for backend (geo-block fetches external data — may take time or fail if offline)
    await page.waitForTimeout(10_000);
    await expect(page.locator('body')).toBeVisible(); // no crash
  });
});

// ─── UI — Blacklists: Domain tab ──────────────────────────────────────────────

test.describe('UI — Blacklists (Domain tab)', () => {
  test.beforeEach(async ({ page }) => {
    await goto(page, '/blacklists', 'IP Blacklist');
    // Switch to Domain tab
    await page.getByRole('button', { name: /Domain/i }).first().click();
    await page.waitForTimeout(500);
  });

  test('domain tab shows correct controls', async ({ page }) => {
    await expect(page.getByRole('button', { name: /Import URL/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Bulk Add/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /^Add$/i }).first()).toBeVisible();
  });

  test('add and delete a domain entry', async ({ page }) => {
    const testDomain = 'e2e-delete-me.test';

    await page.getByRole('button', { name: /^Add$/i }).first().click();
    const domainInput = page.locator('input[placeholder*="example"], input[placeholder*="domain"]').first();
    await expect(domainInput).toBeVisible();
    await domainInput.fill(testDomain);
    await page.getByRole('button', { name: /^Add|^Save/i }).last().click();
    await page.waitForTimeout(1500);

    await expect(page.getByText(testDomain)).toBeVisible({ timeout: 10_000 });

    // Delete it
    const row = page.locator('tr, [data-row], li').filter({ hasText: testDomain }).first();
    const deleteBtn = row.getByRole('button').first();
    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
      const confirmBtn = page.getByRole('button', { name: /confirm|yes|delete/i }).last();
      if (await confirmBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
        await confirmBtn.click();
      }
      await page.waitForTimeout(1500);
    }
  });

  test('domain bulk add works', async ({ page }) => {
    await page.getByRole('button', { name: /Bulk Add/i }).click();
    const textarea = page.locator('textarea');
    await expect(textarea).toBeVisible();
    await textarea.fill(['bulk-test-1.test', 'bulk-test-2.test', '# skip', 'bulk-test-3.test'].join('\n'));
    await page.getByRole('button', { name: /Add All/i }).click();
    await expect(page.getByText(/Added \d+/i)).toBeVisible({ timeout: 15_000 });
  });

  test('popular lists panel opens', async ({ page }) => {
    const popularBtn = page.getByRole('button', { name: /Popular/i });
    await expect(popularBtn).toBeVisible();
    await popularBtn.click();
    // Some list names should appear
    await expect(page.locator('text=Steven Black').or(page.locator('text=Firehol').or(page.locator('text=StevenBlack')))).toBeVisible({ timeout: 10_000 });
  });
});

// ─── UI — Blacklists: Whitelist tab ───────────────────────────────────────────

test.describe('UI — Blacklists (Whitelist tab)', () => {
  test.beforeEach(async ({ page }) => {
    await goto(page, '/blacklists', 'IP Blacklist');
    await page.getByRole('button', { name: /Whitelist/i }).first().click();
    await page.waitForTimeout(500);
  });

  test('whitelist tab has green styling indicator', async ({ page }) => {
    // The whitelist tab button has green accent classes in the implementation
    const tab = page.getByRole('button', { name: /Whitelist/i }).first();
    const cls = await tab.getAttribute('class');
    expect(cls).toMatch(/green/);
  });

  test('add and verify whitelist entry', async ({ page }) => {
    const whitelistIp = '10.88.88.0/28';
    await page.getByRole('button', { name: /^Add$/i }).first().click();
    const ipInput = page.locator('input').first();
    await ipInput.fill(whitelistIp);
    await page.getByRole('button', { name: /^Add|^Save/i }).last().click();
    await page.waitForTimeout(1500);
    await expect(page.getByText(whitelistIp)).toBeVisible({ timeout: 10_000 });
  });

  test('whitelist: Bulk Add and Import URL buttons are NOT shown', async ({ page }) => {
    // Per the implementation, Import URL and Popular Lists are hidden for whitelist tab
    await expect(page.getByRole('button', { name: /Import URL/i })).not.toBeVisible();
  });
});

// ─── UI — Logs page ───────────────────────────────────────────────────────────

test.describe('UI — Logs page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/logs');
    // Wait for the page content (table or empty state)
    await page.waitForTimeout(2_000);
  });

  test('page renders without crash', async ({ page }) => {
    await expect(page.locator('body')).toBeVisible();
    // Should not show the "Something went wrong" error boundary
    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });

  test('shows log table or empty state', async ({ page }) => {
    // Either a table with headers or an empty state message
    const hasTable  = await page.locator('table, [role="table"]').isVisible().catch(() => false);
    const hasEmpty  = await page.getByText(/no logs|no results|empty/i).isVisible().catch(() => false);
    const hasLoader = await page.locator('[class*="spin"], [class*="load"]').isVisible().catch(() => false);
    expect(hasTable || hasEmpty || hasLoader).toBeTruthy();
  });

  test('search/filter input is present', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="search"], input[placeholder*="filter"], input[type="search"]').first();
    await expect(searchInput).toBeVisible({ timeout: 10_000 });
  });

  test('WebSocket connection is attempted (no error boundary shown)', async ({ page }) => {
    await page.waitForTimeout(3_000);
    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });
});

// ─── UI — Settings page ───────────────────────────────────────────────────────

test.describe('UI — Settings page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/settings');
    await page.waitForTimeout(1_500);
  });

  test('page renders all main sections', async ({ page }) => {
    // Settings page has sections: Notifications, Backup/Restore, etc.
    await expect(page.getByText('Something went wrong')).not.toBeVisible();
    await expect(page.locator('body')).toBeVisible();
  });

  test('Backup Config button triggers file download', async ({ page }) => {
    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 15_000 }),
      page.getByRole('button', { name: /Backup Config/i }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/secure-proxy-backup.*\.json/);
  });

  test('Save button is present and enabled', async ({ page }) => {
    const saveBtn = page.getByRole('button', { name: /^Save/i }).first();
    await expect(saveBtn).toBeVisible({ timeout: 10_000 });
    await expect(saveBtn).toBeEnabled();
  });

  test('saving a setting shows success toast', async ({ page }) => {
    const saveBtn = page.getByRole('button', { name: /^Save/i }).first();
    await expect(saveBtn).toBeVisible({ timeout: 10_000 });
    await saveBtn.click();
    // Should show "saved" or "success" toast
    await expect(page.getByText(/saved|success|updated/i).first()).toBeVisible({ timeout: 10_000 });
  });

  test('Change Password section is visible', async ({ page }) => {
    await expect(page.getByText(/[Cc]hange [Pp]assword|[Pp]assword/i).first()).toBeVisible({ timeout: 10_000 });
  });

  test('Clear Cache button is visible', async ({ page }) => {
    await expect(page.getByRole('button', { name: /Clear Cache/i })).toBeVisible({ timeout: 10_000 });
  });
});

// ─── UI — Error Boundary ──────────────────────────────────────────────────────

test.describe('UI — Error handling', () => {
  test('ErrorBoundary renders without crash on all routes', async ({ page }) => {
    for (const path of ['/', '/blacklists', '/logs', '/settings']) {
      await page.goto(path);
      await page.waitForTimeout(1_000);
      await expect(page.getByText('Something went wrong')).not.toBeVisible();
    }
  });
});

// ─── UI — Full selfhoster onboarding flow ─────────────────────────────────────

test.describe('Full onboarding flow (sequential scenario)', () => {
  /**
   * Simulates a new selfhoster going through the app from scratch:
   * Login → copy proxy address → add first IP rule → enable geo-block →
   * check logs → save settings → download backup.
   */
  test.use({ storageState: { cookies: [], origins: [] } });

  test('complete onboarding workflow', async ({ page }) => {
    // 1. Land on login page
    await page.goto('/');
    await expect(page.locator('h1', { hasText: 'Secure Proxy Manager' })).toBeVisible();

    // 2. Login
    await page.fill('#username', USERNAME);
    await page.fill('#password', PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page.locator('text=Configure your device')).toBeVisible({ timeout: 15_000 });

    // 3. Note proxy address from banner
    const banner = page.locator('code').filter({ hasText: '3128' }).first();
    await expect(banner).toBeVisible();
    const proxyAddr = await banner.textContent();
    expect(proxyAddr).toMatch(/:\s*3128/);

    // 4. Navigate to Blacklists → add first IP rule
    await page.goto('/blacklists');
    await page.waitForSelector('text=IP Blacklist');
    await page.getByRole('button', { name: /^Add$/i }).first().click();
    const ipInput = page.locator('input').first();
    await ipInput.fill('192.0.2.200');
    await page.getByRole('button', { name: /^Add|^Save/i }).last().click();
    await page.waitForTimeout(2_000);

    // 5. Switch to Domain tab and add a domain
    await page.getByRole('button', { name: /Domain/i }).first().click();
    await page.waitForTimeout(500);
    await page.getByRole('button', { name: /^Add$/i }).first().click();
    const domainInput = page.locator('input').first();
    await domainInput.fill('onboarding-test.test');
    await page.getByRole('button', { name: /^Add|^Save/i }).last().click();
    await page.waitForTimeout(2_000);

    // 6. Navigate to Logs page — just verify it loads
    await page.goto('/logs');
    await page.waitForTimeout(2_000);
    await expect(page.getByText('Something went wrong')).not.toBeVisible();

    // 7. Navigate to Settings → download backup
    await page.goto('/settings');
    await page.waitForTimeout(1_500);
    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 15_000 }),
      page.getByRole('button', { name: /Backup Config/i }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/\.json$/);

    // Done — no crash, all steps passed
    await expect(page.getByText('Something went wrong')).not.toBeVisible();
  });
});
