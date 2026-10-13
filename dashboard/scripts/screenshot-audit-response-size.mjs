// Real-stack screenshots for the "Response size" line on /audit rows.
//
// Seeds a buffered execution and a streamed one through the real gateway, so
// the audit log carries `detail.size` on `action.executed` and the bytes a
// stream actually carried on `action.stream_completed`. Then expands each.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/audit-size-*.png.

import { login, makeSnapper, seedExecution } from '../tests/scenarios/index.mjs';

const session = await login('admin');

await seedExecution(session, { url: `${session.apiUrl}/health` });
await seedExecution(session, { url: `${session.apiUrl}/health`, preferStream: true });

const snap = await makeSnapper(session);

/** Filter the table to one event kind, expand its newest row, snap. */
async function expandEvent(name, event) {
	const { page, ctx } = await snap.navigateAndSnap(`${name}-list`, '/audit', {
		viewport: { width: 1400, height: 900 },
		waitFor: async (p) => {
			await p.locator('.search input').first().waitFor({ timeout: 15_000 });
		}
	});
	const input = page.locator('.search input').first();
	await input.click();
	await input.fill(`event = ${event}`);
	await input.press('Enter');
	await page.locator('tr.row').first().waitFor({ timeout: 15_000 });
	await page.locator('tr.row').first().click();
	await page.getByText('Response size').first().waitFor({ timeout: 10_000 });
	await snap.snap(page, name);
	await ctx.close();
}

try {
	await expandEvent('audit-size-executed', 'action.executed');
	await expandEvent('audit-size-stream-completed', 'action.stream_completed');
	console.log('[audit-size] done');
} finally {
	await snap.close();
}
