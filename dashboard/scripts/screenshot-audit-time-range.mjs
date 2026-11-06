// Real-stack screenshots for the audit log's time-range picker and the
// server-side export menu.
//
// Seeds a few real events, then captures: the default (24h preselected), a
// preset switch, the custom-range popover, the Export menu, and the empty
// state's "try a wider range" button. Also downloads both export formats
// through the real link and checks they hold every row the API reports for the
// same window — the export covers the window, not the rows on screen.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/audit-range-*.png.

import { api, login, makeSnapper, seedExecution, seedSecret } from '../tests/scenarios/index.mjs';

const session = await login('admin');

await seedSecret(session, { name: `audit-range-demo-${Date.now()}`, value: 'hunter2' });
// Unreachable on purpose: the gateway answers 502 and still writes the
// `action.executed` row, which is all the table needs.
await seedExecution(session, { url: 'http://127.0.0.1:9/unreachable', expect: 502 });
await seedExecution(session, { url: 'http://127.0.0.1:9/also-unreachable', expect: 502 });

const snap = await makeSnapper(session);
const VIEWPORT = { width: 1400, height: 900 };
const waitRows = async (p) => {
	await p.locator('tr.row').first().waitFor({ timeout: 15_000 });
	await p.waitForTimeout(400);
};

try {
	// 1. Default: no window in the URL → 24h preselected.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-range-default', '/audit', {
			viewport: VIEWPORT,
			waitFor: waitRows
		});
		const active = await page.locator('[data-test="audit-time-range"] .seg.active').innerText();
		if (active.trim() !== '24h') throw new Error(`default preset is ${active}, want 24h`);

		// 2. Switch to 1h.
		await page.locator('[data-test="audit-time-range"] .seg', { hasText: '1h' }).click();
		await page.waitForTimeout(600);
		if (!page.url().includes('range=1h')) throw new Error(`URL lacks range=1h: ${page.url()}`);
		await snap.snap(page, 'audit-range-1h');

		// 3. Custom popover, seeded from the active window.
		await page.locator('[data-test="audit-time-range"] .seg.custom').click();
		await page.locator('[data-test="range-since"]').waitFor();
		await page.waitForTimeout(200);
		await snap.snap(page, 'audit-range-custom-popover');
		await page.locator('.pop button', { hasText: 'Apply' }).click();
		await page.waitForTimeout(600);
		if (!page.url().includes('since=')) throw new Error(`custom range not in URL: ${page.url()}`);
		await snap.snap(page, 'audit-range-custom-applied');

		// 4. Export menu.
		await page.locator('[data-test="audit-export"] summary').click();
		await page.waitForTimeout(200);
		await snap.snap(page, 'audit-range-export-menu');

		// 5. Downloads go through the real link and cover the whole window.
		const href = await page
			.locator('[data-test="audit-export"] a', { hasText: 'JSONL' })
			.getAttribute('href');
		const qs = new URLSearchParams(href.split('?')[1]);
		const listed = await api(
			session,
			`/v1/audit?limit=1000&since=${encodeURIComponent(qs.get('since'))}&until=${encodeURIComponent(qs.get('until'))}`
		);
		for (const [label, lines] of [
			['CSV', (t) => t.split('\r\n').filter(Boolean).length - 1],
			['JSONL', (t) => t.split('\n').filter(Boolean).length]
		]) {
			const [download] = await Promise.all([
				page.waitForEvent('download'),
				page.locator('[data-test="audit-export"] a', { hasText: label }).click()
			]);
			const stream = await download.createReadStream();
			let body = '';
			for await (const chunk of stream) body += chunk;
			const n = lines(body);
			console.log(`${label}: ${download.suggestedFilename()} — ${n} rows (API lists ${listed.length})`);
			// The export runs a moment after the list, and an export of the window
			// itself writes a row — but only *after* `until`, so counts match.
			if (n !== listed.length) throw new Error(`${label} export has ${n} rows, API ${listed.length}`);
			// Reopen the menu for the next link.
			await page.locator('[data-test="audit-export"] summary').click();
		}
		await ctx.close();
	}

	// 6. Empty state: 5m and a filter nothing matches → "Try 1h".
	{
		const { page, ctx } = await snap.navigateAndSnap(
			'audit-range-empty',
			'/audit?range=5m&action=no.such.event',
			{
				viewport: VIEWPORT,
				waitFor: async (p) => {
					await p.locator('.state.muted button', { hasText: 'Try 1h' }).waitFor({ timeout: 15_000 });
				}
			}
		);
		await ctx.close();
	}

	// 7. An id deep link has no window: older than any preset, still found.
	{
		const [{ id }] = await api(session, '/v1/audit?limit=1');
		const { page, ctx } = await snap.navigateAndSnap('audit-range-id-lookup', `/audit?uuid=${id}`, {
			viewport: VIEWPORT
		});
		await page.locator('[data-test="audit-time-range"] .seg.custom', { hasText: 'whole history' }).waitFor();
		await ctx.close();
	}
} finally {
	await snap.close();
}
