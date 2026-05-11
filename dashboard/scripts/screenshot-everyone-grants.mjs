// Real-stack screenshots for removing bootstrapped grants from the
// Everyone system group. Drives the actual dashboard against the e2e
// stack — no route interception, so the captured PNGs reflect what
// users see when they wire down the org's default access surface.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/everyone-*.png.

import { login, makeSnapper, api } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);

try {
	const groups = await api(session, '/v1/groups');
	const everyone = groups.find((g) => g.system_kind === 'everyone');
	if (!everyone) throw new Error('Everyone system group not found on the running stack');

	// 1. Everyone detail page with the bootstrapped overslash + http grants
	// visible. Captures the "before" state.
	await snap
		.navigateAndSnap('everyone-grants', `/org/groups/${everyone.id}`, {
			viewport: { width: 1280, height: 800 },
			waitFor: async (p) => {
				await p.getByText('overslash').first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(400);
			}
		})
		.then((r) => r.ctx.close());

	// 2. Warning modal: click Remove on the `overslash` row, capture the
	// ConfirmModal that asks for explicit confirmation before stripping
	// the org-wide metaservice default.
	{
		const { page, ctx } = await snap.navigateAndSnap(
			'everyone-grants-loaded',
			`/org/groups/${everyone.id}`,
			{
				viewport: { width: 1280, height: 800 },
				waitFor: async (p) => {
					await p.getByText('overslash').first().waitFor({ timeout: 15_000 });
				}
			}
		);

		const overslashRow = page
			.getByRole('row')
			.filter({ has: page.locator('code', { hasText: /^overslash$/ }) });
		await overslashRow.getByRole('button', { name: /Remove/i }).first().click();
		await page.getByRole('dialog').waitFor({ timeout: 5_000 });
		await page.waitForTimeout(300);
		await snap.snap(page, 'everyone-remove-overslash-modal');
		await ctx.close();
	}

	// 3. Same for http.
	{
		const { page, ctx } = await snap.navigateAndSnap(
			'everyone-grants-http',
			`/org/groups/${everyone.id}`,
			{
				viewport: { width: 1280, height: 800 },
				waitFor: async (p) => {
					await p.getByText('http').first().waitFor({ timeout: 15_000 });
				}
			}
		);
		const httpRow = page.getByRole('row').filter({ has: page.locator('code', { hasText: /^http$/ }) });
		await httpRow.getByRole('button', { name: /Remove/i }).first().click();
		await page.getByRole('dialog').waitFor({ timeout: 5_000 });
		await page.waitForTimeout(300);
		await snap.snap(page, 'everyone-remove-http-modal');
		await ctx.close();
	}

	console.log('[everyone-grants] done');
} finally {
	await snap.close();
}
