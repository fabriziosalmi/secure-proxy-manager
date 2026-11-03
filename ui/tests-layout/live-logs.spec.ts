/**
 * The access log's live feed puts each new row at the top of the table. A
 * row that moves while the pointer is on it can be clicked by mistake: the
 * operator aims at one request and opens the one that took its place. This
 * spec puts the pointer on a row, sends live rows over the feed, and asks
 * which row is under the pointer then: the same one, the new rows held
 * until the pointer leaves the table.
 */
import { expect, test, type WebSocketRoute } from '@playwright/test';
import { mockApi } from './fixtures';

function liveRow(n: number) {
  return {
    id: 5000 + n, timestamp: `2026-10-29 07:52:${String(n).padStart(2, '0')}`, source_ip: '10.20.0.50', method: 'CONNECT',
    destination: `live-${n}.example.com:443`, status: 'TCP_TUNNEL/200', bytes: 100, blocked: false, reason: 'none',
    reason_label: 'Allowed', internal: false, kind: 'Private network address', resolved_ip: '192.0.2.10', event_id: null,
  };
}

test('a live row does not move the row under the pointer', async ({ page }) => {
  const unknown = await mockApi(page);
  // Routes registered later win: this one answers the feed's token.
  await page.route('**/api/ws-token', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"token":"t"}' }));
  let feed: WebSocketRoute | undefined;
  await page.routeWebSocket(/\/api\/ws\/logs$/, (ws) => { feed = ws; });

  await page.goto('/logs');
  await expect(page.getByRole('heading', { level: 1, name: 'Access logs' })).toBeVisible();
  await expect.poll(() => feed !== undefined).toBe(true);
  const rows = page.locator('table tbody tr', { hasText: 'clientservices.googleapis.com' });
  await expect(rows).toHaveCount(6);

  const target = rows.nth(2);
  // On a phone the row is below the fold: bring it into view first, so the
  // page is scrolled there, the other case scroll anchoring may cover.
  await target.scrollIntoViewIfNeeded();
  const box = (await target.boundingBox())!;
  const x = box.x + box.width / 2;
  const y = box.y + box.height / 2;
  await page.mouse.move(x, y);
  const rowAt = () => page.evaluate(([px, py]) => document.elementFromPoint(px, py)?.closest('tr')?.textContent ?? '', [x, y]);
  const before = await rowAt();
  expect(before).toContain('clientservices.googleapis.com');

  for (let n = 1; n <= 3; n++) feed!.send(JSON.stringify(liveRow(n)));
  // Held while the pointer is on the table, and said so.
  await expect(page.getByRole('status', { name: 'Held live rows' })).toHaveText('3 new requests, shown when you leave the table');
  expect(await rowAt(), 'the row under the pointer changed when live rows arrived').toBe(before);

  // In when the pointer leaves the table.
  await page.mouse.move(0, 0);
  await expect(page.getByText('live-3.example.com:443').first()).toBeVisible();
  await expect(page.getByRole('status', { name: 'Held live rows' })).toHaveText('');
  expect([...unknown], 'API paths the fixtures do not answer').toEqual([]);
});
