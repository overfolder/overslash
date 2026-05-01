// Real-stack screenshots for /audit.
//
// Replaces screenshot-audit-mocked.mjs. Drives a handful of real actions
// (secret put, identity create, approval gap) so the audit log has a few
// distinct event kinds to render, then captures the populated, expanded,
// search, and empty states.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/audit-*.png.

import {
	login,
	makeSnapper,
	seedAgent,
	seedApproval,
	seedSecret
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

// 1. Generate real audit traffic. Each helper hits the real API; the
//    server writes the audit row from inside the request handler.
await seedSecret(session, { name: `audit-demo-${Date.now()}`, value: 'hunter2' });
await seedAgent(session, { name: `audit-demo-agent-${Date.now()}` });
await seedApproval(session); // approval.created + identity.created upstream

const snap = await makeSnapper(session);

try {
	// 2. Populated.
	const { page, ctx } = await snap.navigateAndSnap('audit-populated', '/audit', {
		viewport: { width: 1400, height: 900 },
		waitFor: async (p) => {
			// The exact action text varies (secret.put / identity.created /
			// approval.created) so just wait for any audit row to render.
			await p.locator('tr.row').first().waitFor({ timeout: 15_000 });
			await p.waitForTimeout(500);
		}
	});

	// 3. Expanded row — click the first row.
	const firstRow = page.locator('tr.row').first();
	if ((await firstRow.count()) > 0) {
		await firstRow.click();
		await page.waitForTimeout(400);
		await snap.snap(page, 'audit-expanded');
	}
	await ctx.close();

	// 4. Search bar with chip + autocomplete.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-search', '/audit', {
			viewport: { width: 1400, height: 900 },
			waitFor: async (p) => {
				await p.locator('.search input').first().waitFor({ timeout: 15_000 });
			}
		});
		const input = page.locator('.search input').first();
		await input.click();
		await input.fill('event = secret.put');
		await input.press('Enter');
		await page.waitForTimeout(150);
		await input.fill('ide');
		await page.waitForTimeout(400); // past the 200ms debounce
		await snap.snap(page, 'audit-search');
		await ctx.close();
	}

	// 5. Empty state — filter to a key that nothing matches.
	{
		const { page, ctx } = await snap.navigateAndSnap('audit-empty', '/audit', {
			viewport: { width: 1400, height: 900 },
			waitFor: async (p) => {
				await p.locator('.search input').first().waitFor({ timeout: 15_000 });
			}
		});
		const input = page.locator('.search input').first();
		await input.click();
		await input.fill('event = nothing.ever.matches');
		await input.press('Enter');
		await page.waitForTimeout(400);
		await snap.snap(page, 'audit-empty');
		await ctx.close();
	}

	console.log('[audit] done');
} finally {
	await snap.close();
}
